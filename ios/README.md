# iPhone / iPad native client source

This folder contains the native SwiftUI Router VPN application plus its NetworkExtension Packet Tunnel target. The shipping iOS/iPadOS path is not a controller/importer-only shell: raw WireGuard and AmneziaWG Fast/Strong use the pinned WireGuardKit adapter (the AWG-capable upstream fork) and supported layered/external paths use the pinned Libbox bridge inside the PacketTunnel.

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

- real pinned AWG-capable WireGuardKit PacketTunnel for raw WireGuard and AmneziaWG Fast/Strong;
- saved WG/AWG base preference and explicitly permitted fallback, with exact-raw CUSTOM/SMART/last-good dispatch;
- fixed dual-stack MTU applied to the actual native WG/AWG, Router Libbox and external Libbox TUNs;
- tunnel-owned server forwarding-master control, with private node/session proof and independent readback;
- pinned Libbox PacketTunnel paths for the supported Router VPN layered modes;
- supported external WireGuard, SOCKS5, HTTP(S) CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN TLS-client exits through the real Apple dataplane;
- one owned multihop PacketTunnel with a WireGuard entry and WireGuard/Shadowsocks/Hysteria2 Router VPN exit, independent node proofs, saved graph profiles and temporary Speed Lab transactions;
- strict NetworkExtension route-lockdown controls where requested;
- selected-node/private-path and expected-public-exit proof before Connected.

Do **not** infer desktop parity from the UI. Mobile OpenVPN is implemented for the explicit bounded profile subset documented in `docs/MOBILE-OPENVPN.md`; arbitrary OpenVPN directives are not silently ignored. Generalized desktop-equivalent multihop, mobile helper/PQ composites and unsupported mixed graphs still require implementation. Server forwarding-master control is implemented; it is not arbitrary phone-local DNAT. Unsupported paths fail closed for safety, but an unavailable label does not close a feature-parity requirement. See `docs/APPLE-NATIVE-CONTINUATION.md` for this continuation's verified scope and the remaining work.

Physical iPhone/iPad VPN permission, Wi-Fi/cellular transition, reconnect, DNS/IPv4/IPv6 leak-negative behavior and signing/distribution remain release gates beyond source compilation.

## Manual project generation

```bash
brew install xcodegen
cd ios/RouterVPN
sh prepare-wireguard-kit.sh
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
