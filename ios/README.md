# iPhone / iPad native client source

This folder contains the native SwiftUI Router VPN application plus its NetworkExtension Packet Tunnel target. The shipping iOS/iPadOS path is not a controller/importer-only shell: raw WireGuard uses the pinned WireGuardKit adapter and supported layered/external paths use the pinned Libbox bridge inside the PacketTunnel.

## Build artifacts

The authoritative release candidate builds the real unsigned re-signable IPA in:

```text
.github/workflows/release-candidate.yml
```

The reusable native client workflow also produces the same IPA member in:

```text
.github/workflows/client-apps-ci.yml
```

Dedicated compiler/runtime diagnostics live in `ios-native-compile-smoke.yml` and `ios-libbox-engine.yml`. The produced native member is:

```text
RouterVPN-native-unsigned-resignable.ipa
```

See `docs/BUILDS.md` and `docs/NATIVE-APPS.md` for distribution and release gates.

## Runtime truth / limitations

Current source supports:

- real pinned WireGuardKit PacketTunnel for raw WireGuard;
- pinned Libbox PacketTunnel paths for the supported Router VPN layered modes;
- supported external WireGuard, SOCKS5, Shadowsocks and Hysteria2 exits through the real Apple dataplane;
- strict NetworkExtension route-lockdown controls where requested;
- selected-node/private-path and expected-public-exit proof before Connected.

Do **not** infer desktop parity from the UI. Native iOS AmneziaWG, OpenVPN, arbitrary desktop-equivalent multihop, arbitrary DNAT/forwarding-master enforcement, and unsupported mixed graphs remain unavailable until a real pinned Apple dataplane implements them. Unsupported paths fail closed rather than reporting fake readiness or Connected.

Physical iPhone/iPad VPN permission, Wi-Fi/cellular transition, reconnect, DNS/IPv4/IPv6 leak-negative behavior and signing/distribution remain release gates beyond source compilation.

## Manual project generation

```bash
brew install xcodegen
cd ios/RouterVPN
./prepare-wireguard-kit.sh
./prepare-libbox.sh
xcodegen generate
open RouterVPN.xcodeproj
```

Use these bundle identifiers:

```text
com.eabusham.routervpn
com.eabusham.routervpn.PacketTunnel
```

Both App IDs and provisioning profiles need the Packet Tunnel Network Extension entitlement.
