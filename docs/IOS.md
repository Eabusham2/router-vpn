# iPhone and iPad

The ZIP contains the native SwiftUI interface, bundle importer, mode list, DAITA/Jumbo controls, port-forward controls, and Packet Tunnel extension target.

A signed working IPA is not included. It cannot be validly signed without your Apple Developer Team, provisioning profiles, Network Extension capability, and a linked tunnel engine.

## Build the project

On a Mac:

```bash
brew install xcodegen
cd router-vpn/ios/RouterVPN
xcodegen generate
open RouterVPN.xcodeproj
```

Then in Xcode:

1. Select your Apple Team for both targets.
2. Enable **Network Extensions → Packet Tunnel** for both App IDs/targets.
3. Link an iOS-capable WireGuard/AmneziaWG and proxy engine to `RouterVPNPacketTunnel`.
4. Replace the intentional placeholder in `PacketTunnelProvider.swift` with that engine adapter.
5. Product → Archive.
6. Distribute as Development, Ad Hoc, TestFlight, or App Store using your provisioning profile.

The included GitHub iOS workflow also requires your signing certificate and provisioning secrets before it can produce an IPA.
