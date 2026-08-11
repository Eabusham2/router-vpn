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

The current `PacketTunnelProvider.swift` **intentionally fails closed** with an `NSError` and calls `completionHandler(error)` because the native WireGuard/AmneziaWG/Xray/sing-box adapter is not linked yet. That error path is expected preview behavior, not an accidental Go/Swift error or failed exception-handling path. It prevents a signed UI-only build from pretending the VPN connected.

CI compiles both the app and Packet Tunnel target and explicitly checks that this fail-closed behavior remains present until real adapters replace it.

## GitHub Actions IPA builds

The client CI builds:

```text
RouterVPN-preview-unsigned-resignable.ipa
```

This preview IPA must be re-signed before installation and is **not** advertised as a working full-device VPN while the native tunnel adapters are absent.

Signing by itself does not add the missing tunnel engine. The custom app becomes a working full-device VPN only after native adapters are linked and validated in `PacketTunnelProvider.swift`.

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
4. Replace the current explicit fail-closed error with the real adapter implementation.
5. Build to a device or archive and export.

Bundle identifiers:

```text
com.eabusham.routervpn
com.eabusham.routervpn.PacketTunnel
```
