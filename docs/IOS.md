# iPhone and iPad

No home-router address is embedded in the app. Router profiles are imported and edited at runtime.

## Immediate usable profiles

After the router installs, open the private client bundle:

- `generated/wg/wg.conf` → import into WireGuard
- `generated/awg2-fast/awg.conf` → import into an AmneziaWG-compatible iOS client

## Custom Router VPN IPA

A signed IPA is not bundled. Apple requires your own Developer Team, app and extension provisioning profiles, and Packet Tunnel entitlement. The included Packet Tunnel target is a scaffold until the AWG/WireGuardKit adapter is linked.

### Build

1. Install Xcode on a Mac.
2. Install XcodeGen:

```bash
brew install xcodegen
```

3. Open Terminal and run:

```bash
cd /path/to/router-vpn/ios/RouterVPN
xcodegen generate
open RouterVPN.xcodeproj
```

4. Select your Apple Developer Team for `RouterVPN` and `RouterVPNPacketTunnel`.
5. Enable **Network Extensions → Packet Tunnel** for both App IDs.
6. Add the AmneziaWG Apple/WireGuardKit package and its required Go bridge target to the Packet Tunnel target.
7. Replace the placeholder in `PacketTunnelProvider.swift` with the engine adapter.
8. Product → Archive → Distribute App → Development or Ad Hoc.

The private repo also includes `.github/workflows/build-ios.yml`; it requires your Apple certificate, provisioning profiles, Team ID, and the completed tunnel adapter.
