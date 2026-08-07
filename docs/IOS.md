# iPhone and iPad

No home-router address is embedded in the app. Router profiles are imported and edited at runtime.

## Immediate working profiles

After the router installs, open the private client bundle:

- `generated/wg/wg.conf` → import into WireGuard
- `generated/awg2-fast/awg.conf` → import into an AmneziaWG-compatible iOS client

These are the immediate iPhone/iPad choices while the custom Packet Tunnel adapter is unfinished.

## Custom Router VPN app

The SwiftUI app includes:

- router-bundle import
- runtime endpoint editing
- all generated modes and overhead display
- AUTO/manual controls
- DAITA-like and Jumbo controls
- SOCKS5 IP:port display
- WG/AWG port-forward controls
- Packet Tunnel extension target

The current `PacketTunnelProvider.swift` intentionally returns an error explaining that the native WireGuard, AmneziaWG, Xray, and sing-box adapter is not linked. This prevents a signed UI-only app from pretending the VPN connected.

## GitHub Actions IPA builds

Run **Actions → Build all platforms**.

Without Apple secrets, the workflow builds:

```text
RouterVPN-unsigned-resignable.ipa
```

This IPA must be re-signed before installation.

With all Apple secrets configured, it also attempts to build:

```text
RouterVPN-signed.ipa
RouterVPN.xcarchive
```

See `docs/BUILDS.md` for the five required secrets, bundle identifiers, and Base64 commands.

Signing does not add the missing tunnel engine. The custom app becomes a working VPN only after a native adapter is linked in `PacketTunnelProvider.swift`.

## Build manually on a Mac

```bash
brew install xcodegen
cd ios/RouterVPN
xcodegen generate
open RouterVPN.xcodeproj
```

Then:

1. Select your Apple Developer Team for both targets.
2. Enable the Packet Tunnel Network Extension entitlement for both App IDs.
3. Add the required WireGuard/AmneziaWG and proxy-engine libraries to the Packet Tunnel target.
4. Replace the current explicit placeholder error with the real adapter.
5. Build to a device or archive and export.

Bundle identifiers:

```text
com.eabusham.routervpn
com.eabusham.routervpn.PacketTunnel
```
