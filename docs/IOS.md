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
- Raw AmneziaWG Fast/Strong profiles use the pinned native Apple WireGuard-family engine. AWG/PQ and other composites still require their additional real engine layers.
- The multihop candidate adds a raw WireGuard entry followed by a Router VPN Shadowsocks/Hysteria2 exit in one Libbox PacketTunnel; full desktop-equivalent and external-exit mixed graphs remain unfinished.
- External OpenVPN remains unavailable because Router VPN does not ship a pinned native Apple OpenVPN dataplane.
- MAX/ALL labels do not make an unsupported Apple graph Ready.

Unsupported paths fail closed rather than substituting another engine or faking Connected.


## Two-hop implementation candidate

The local continuation based on `f73b177e49915a68c6d36ad99fe93bd802e3cda9` adds a native **Multihop** editor, non-secret whole-profile graph save/load, and current/temporary Speed Lab paths. It is an **unpublished source candidate**, not a newly certified native release. The baseline's green build does not certify these changes.

The implemented graph is **paired Router VPN raw WireGuard entry → paired Router VPN Shadowsocks/Hysteria2 exit**. Both transport endpoints, the entry's private SOCKS endpoint, and the selected DNS resolver must be literal addresses. The entry must supply full dual-stack allowed routes; Start Layers, DAITA and Jumbo must be off. A requested LAN-Off policy is rejected because this candidate does not yet own its filtering. Existing split/bypass and custom DNS rules are rejected rather than erased. Ordinary data and DNS traverse the encrypted exit with no direct-exit fallback. IPv6 Off on either node is enforced by an in-TUN reject while retaining the IPv6 default capture.

The extension captures complete entry and exit bundles before startup and owns one Libbox instance. Private `/health` checks are independently routed through loopback-only entry port 1098 and exit port 1099. Both paired identities and the still-owned engine must match before connection completion or exit forwarding-master availability. These identity checks are not a substitute for physical public-exit/leak testing.

Connection profiles retain only node references and graph choices, never copied keys or tokens. Loading another node fetches that node's complete private bundle. Speed Lab can test an already saved graph temporarily and uses its existing persistence-recovery journal and teardown path. Speed Lab compares the actual NetworkExtension connection date and frozen entry/exit bundle bytes, not only displayed node/mode labels; a reconnect or graph replacement invalidates the measurement. Unknown tunnel status locks mutation/measurement instead of pretending the VPN is disconnected. Direct cached node RTT is not relabeled as routed-hop RTT. Independent per-hop throughput/latency on iOS remains unfinished.

`deploy/test_ios_multihop_graph.py` and `deploy/test_ios_multihop_profiles.py` execute shipping graph/serialization logic offline. The native build also invokes `deploy/test_ios_multihop_pinned.sh`, which compiles the CLI from the exact shipped Libbox source pin and runs configuration checks (not tunnels). The candidate still needs that native gate, Xcode compilation, signed-device install, actual two-node traffic/exit/DNS/leak proof, reconnect/cancel/permission tests, and a same-SHA release.

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
