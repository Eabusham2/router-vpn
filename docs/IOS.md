# iPhone/iPad

A signed IPA cannot be bundled without your Apple signing identity and Network Extension provisioning. The SwiftUI app, Packet Tunnel target, entitlements, XcodeGen project, and GitHub Actions signing workflow are included.

## Build the IPA

1. On a Mac, install Xcode from the App Store.
2. Install XcodeGen:

```bash
brew install xcodegen
```

3. Open Terminal and enter:

```bash
cd /path/to/router-vpn/ios/RouterVPN
xcodegen generate
open RouterVPN.xcodeproj
```

4. In Xcode, select your Apple Developer Team for `RouterVPN` and `RouterVPNPacketTunnel`.
5. Enable **Network Extensions → Packet Tunnel** for both App IDs in Apple Developer.
6. Add the AmneziaWG Apple package to the Packet Tunnel target.
7. Link its WireGuardKit/Go bridge as described in `ios/README.md`.
8. Replace the marked PacketTunnel placeholder with the included engine adapter work.
9. Choose **Product → Archive → Distribute App → Development/Ad Hoc**.

The GitHub workflow `.github/workflows/build-ios.yml` can export the IPA after adding its Apple signing secrets.

## Immediate iPhone fallback

Import `generated/awg2-fast/awg.conf` into the AmneziaWG App Store app, or `generated/wg/wg.conf` into WireGuard. This uses the router server immediately but does not provide the custom all-mode picker.
