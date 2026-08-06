# iPhone/iPad build

This folder is the native SwiftUI app, mode picker, bundle importer, Network Extension target, DAITA/jumbo controls, and port-forward control surface.

A signed IPA is not included because Apple requires your own Developer Team, provisioning profile, and Packet Tunnel entitlement. The PacketTunnel target intentionally fails until an approved tunnel engine is linked.

## Build

1. On a Mac install Xcode and XcodeGen: `brew install xcodegen`.
2. Open Terminal: `cd ios/RouterVPN && xcodegen generate && open RouterVPN.xcodeproj`.
3. Select your Apple Team for both targets.
4. Add the AmneziaWG Apple package from `https://github.com/amnezia-vpn/amneziawg-apple` and link `WireGuardKit` to the PacketTunnel target.
5. Replace the placeholder in `PacketTunnelProvider.swift` with the engine adapter.
6. Set the Network Extension entitlement for both App IDs in Apple Developer.
7. Product → Archive → Distribute App → Development or Ad Hoc.

The GitHub workflow is included, but it only succeeds after repository signing secrets and provisioning profiles are added.
