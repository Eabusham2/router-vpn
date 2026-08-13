# Router VPN native download policy

Router VPN installation packages are generic and contain no linked home/server node. Installing an app and linking a Router VPN node are separate operations.

## Source order

For every authenticated Setup Center package request, the broker scopes GitHub artifacts to the configured repository, branch, and (for releases) exact full `ROUTER_VPN_GITHUB_SHA`.

1. Prefer the matching artifact from the one-SHA Router VPN release-candidate workflow.
2. If that artifact is unavailable, prefer the matching dedicated same-SHA native CI artifact.
3. For desktop/Portable requests only, if no same-SHA GitHub package is available, the home node may run the bounded requested-package-only generic Go fallback. This fallback is not allowed to bake linked-node data into the application package.
4. Android and iOS/iPadOS never use a Linux-host fake mobile build fallback. Their download fails closed until a matching same-SHA mobile artifact exists.

## Platform mapping

- Windows x64/ARM64 installed and Portable packages: release-candidate generic artifact, then `RouterVPN-client-desktop-unix-ci`. These packages launch the native WPF Router VPN app; they do not launch Edge/Chrome or embed a web app.
- macOS x64/ARM64: `RouterVPN-macOS-release-candidate`, then `RouterVPN-macOS-Native-CI`. The selected archive contains the native AppKit `RouterVPN.app`.
- Linux x64/ARM64: the architecture-specific `RouterVPN-Linux-*-release-candidate`, then `RouterVPN-Linux-Native-*-CI`. The selected archive contains the native GTK `router-vpn-app`.
- Android: `RouterVPN-Android-release-candidate`, then `RouterVPN-Android-CI`.
- iOS/iPadOS: `RouterVPN-iOS-release-candidate`, then `RouterVPN-iOS-Native-WireGuard-CI`. The artifact is the unsigned re-signable native WireGuard PacketTunnel IPA. `router-vpn-ios-preview.ipa` remains only as a backward-compatible authenticated alias; new Setup Center pages use `router-vpn-ios.ipa` and do not call the app a preview.

## Security and retention

Artifact ZIP extraction is bounded by member count, member size, total size, compression ratio, safe relative paths, and symlink/device rejection. Generic package validation rejects linked router profiles, generated per-node material, private bundles, and missing MIT license material. Temporary request/build files are private and removed after delivery/cancellation. CI application artifacts use one-day retention.

The authenticated broker never makes private Router VPN control ports public and never uses a floating `latest` release URL as a package source.
