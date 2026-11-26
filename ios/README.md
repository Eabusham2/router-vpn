# iPhone / iPad native client source

This folder contains the native SwiftUI Router VPN application plus its NetworkExtension Packet Tunnel target. Raw WireGuard and AmneziaWG Fast/Strong have a pinned WireGuardKit adapter (the AWG-capable upstream fork); adaptive MTU and supported layered/external paths use the pinned Libbox bridge inside the PacketTunnel. Runtime selection depends on the saved profile and supported graph.

## Installing the app

Start with the [main README](../README.md) and [client guide](../docs/CLIENT.md).
The [GitHub Releases](https://github.com/Eabusham2/router-vpn/releases) page
contains packages only for source commits whose publishing gates completed.
Verify the release checksum and use the same commit as your server. The
`RouterVPN-native-unsigned-resignable.ipa` package requires signing with your own
compatible Apple provisioning; downloading an unsigned IPA does not make it
installable or grant Network Extension entitlements.

## Build artifacts

The manual release workflow builds the real unsigned re-signable IPA after
routine CI succeeds for the same source commit:

```text
.github/workflows/build-all.yml
```

The iOS job compiles the native runtime, app and PacketTunnel before packaging.
The produced native member is:

```text
RouterVPN-native-unsigned-resignable.ipa
```

See [build instructions](../docs/BUILDS.md) and [native application status](../docs/NATIVE-APPS.md) for distribution and release gates.

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

Mobile OpenVPN accepts the explicit profile subset documented in [Mobile OpenVPN](../docs/MOBILE-OPENVPN.md); arbitrary directives are not silently ignored. Graph support varies by runtime and platform. Server forwarding-master control does not provide arbitrary phone-local DNAT. Unsupported paths fail closed with a reason. See [current status](../docs/CURRENT-STATUS.md) and [native application support](../docs/NATIVE-APPS.md) for implemented paths and remaining work.

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

These are the repository's default bundle identifiers. Configure identifiers,
signing team, provisioning profiles and the shared App Group consistently for
your Apple developer account. Both targets need the required Packet Tunnel
Network Extension capability. Use the Xcode/iOS versions and dependency pins
declared by the project and native build workflows.
