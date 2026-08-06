# iPhone and iPad

The iOS source now includes a runtime router picker and editable endpoint. No router address is fixed at build time.

A signed IPA is not bundled because Apple requires your certificate, provisioning profiles, Team ID, and Packet Tunnel entitlement.

## Build/sign

1. Install Xcode on a Mac.
2. Open Terminal.
3. Run:

```bash
brew install xcodegen
cd /path/to/router-vpn/ios/RouterVPN
xcodegen generate
open RouterVPN.xcodeproj
```

4. Select your Apple Developer Team for both targets.
5. Enable **Network Extensions → Packet Tunnel** for both App IDs.
6. Add the AmneziaWG Apple package/engine to the Packet Tunnel target.
7. Archive and export a Development or Ad Hoc IPA.

The private repository includes `.github/workflows/build-ios.yml`. Add the documented Apple signing secrets, then run **Actions → Build signed iOS IPA → Run workflow**.

## Use

1. Import `router-vpn-bundle.json`.
2. Select the router.
3. Enter its public IPv4, global IPv6, or hostname.
4. Select AUTO/manual mode and connect.

Until the Packet Tunnel engine adapter and entitlement are linked, use the generated `awg2-fast/awg.conf` in the Amnezia app or `wg/wg.conf` in WireGuard on iPhone.
