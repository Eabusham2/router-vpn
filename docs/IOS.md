# iPhone and iPad

No home-router address is embedded in the app. Router nodes/profiles are linked or imported at runtime and stored per node.

## Native Router VPN app

The SwiftUI iOS/iPadOS app ships a real Packet Tunnel target. Current source includes:

- private home-LAN linking/import and per-node bundle storage
- exact selected-node identity proof
- native pinned WireGuardKit PacketTunnel for raw WireGuard
- pinned Libbox Apple bridge for supported Router VPN layered profiles
- external WireGuard, SOCKS5, Shadowsocks and Hysteria2 through the Libbox PacketTunnel path
- expected-public-exit proof before external Connected state
- strict NetworkExtension route-lockdown handling using `includeAllNetworks` + `enforceRoutes`
- on-demand reconnect and LAN-policy alignment for strict mode
- logical-mode/base selection with unsupported capabilities remaining unavailable
- node list/current-recent/last-used/name/measured-latency ordering
- no invented map coordinates for coordinate-less nodes

The app follows real NetworkExtension status. It does not mark itself Connected merely because tunnel startup was requested.

## Honest current boundary

The native Apple dataplanes currently present are not equivalent to the complete desktop engine set.

- Raw WireGuard is a real pinned WireGuardKit path.
- Supported imported Router VPN layered profiles use the pinned Libbox bridge.
- External WireGuard/SOCKS5/Shadowsocks/Hysteria2 use the Libbox path with exact expected-exit proof.
- AmneziaWG-only paths remain unavailable until a real pinned Apple AmneziaWG dataplane exists.
- Full desktop-equivalent Router VPN multihop remains unavailable.
- External OpenVPN remains unavailable because Router VPN does not ship a pinned native Apple OpenVPN dataplane.
- MAX/ALL labels do not make an unsupported Apple graph Ready.

Unsupported paths fail closed rather than substituting another engine or faking Connected.

## Setup Center profiles

The private Setup Center can still provide compatible protocol material for independent/native apps when that is useful, including WireGuard and supported compatible-method profiles. These are alternative interoperability paths, not evidence that a Router VPN app capability passed its physical-device release gate.

## GitHub Actions IPA builds

Client/release CI builds the SwiftUI app and PacketTunnel target and packages an **unsigned re-signable IPA** from the exact source SHA. CI verifies the pinned WireGuardKit/Libbox build/runtime contract.

A successful unsigned build proves source/package readiness, not Apple distribution or live full-device behavior. Installation on a normal device requires legitimate signing/provisioning, and final release still requires physical-device validation.

## Build/sign on a Mac

```bash
brew install xcodegen
cd ios/RouterVPN
xcodegen generate
open RouterVPN.xcodeproj
```

Then:

1. Select the intended Apple Developer Team for the app and PacketTunnel targets.
2. Enable/verify the required Network Extension Packet Tunnel entitlement and matching provisioning.
3. Build/archive the existing pinned WireGuardKit + Libbox implementation; do not replace it with the retired fail-closed preview stub.
4. Install to a real device and perform the physical validation matrix before treating the build as release-ready.

Bundle identifiers:

```text
com.eabusham.routervpn
com.eabusham.routervpn.PacketTunnel
```

## Required physical validation

Before final release on iPhone/iPad, prove on real hardware:

- VPN permission and PacketTunnel startup
- exact selected home-node proof
- real public-exit change
- tunneled DNS and IPv4/IPv6 behavior as applicable
- strict route-lockdown / leak-negative behavior
- disconnect/reconnect and network-change/on-demand behavior
- supported Libbox layered traffic
- supported external-exit traffic and exact expected-public-exit proof
- fail-closed behavior for unsupported/invalid paths
- legitimate signing/provisioning behavior

CI, simulator/source checks or a green UI alone do not satisfy this gate.
