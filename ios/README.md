# iPhone/iPad source

This folder contains the SwiftUI controller/importer and Packet Tunnel extension target.

## Build artifacts

Run the single repository workflow:

```text
.github/workflows/build-all.yml
```

It produces an unsigned re-signable IPA on every successful iOS build and an optional signed IPA when the Apple secrets are configured. See `docs/BUILDS.md`.

## Important limitation

`PacketTunnelProvider.swift` intentionally reports that the native tunnel adapter is missing. The IPA can build and be signed, but custom VPN connections will not work until WireGuard/AmneziaWG/Xray/sing-box engine code is linked to the extension.

## Manual project generation

```bash
brew install xcodegen
cd ios/RouterVPN
xcodegen generate
open RouterVPN.xcodeproj
```

Use these bundle identifiers:

```text
com.eabusham.routervpn
com.eabusham.routervpn.PacketTunnel
```

Both App IDs and provisioning profiles need the Packet Tunnel Network Extension entitlement.
