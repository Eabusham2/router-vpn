# Router VPN native download policy

Router VPN installation packages are generic and contain no linked home/server node. Installing an app and linking Router VPN nodes are separate operations.

## Source order

For every authenticated Setup Center package request, the broker scopes GitHub artifacts to the configured repository, branch and, for release downloads, exact full `ROUTER_VPN_GITHUB_SHA`.

1. Prefer the matching artifact from the one-SHA Router VPN release-candidate workflow.
2. If that artifact is unavailable, prefer the matching dedicated same-SHA native CI artifact.
3. For **Windows x64/ARM64 installed and Portable requests only**, if no same-SHA GitHub package is available, the home node may run the bounded requested-package-only generic Windows fallback using the approved same-image prebuilt components. This fallback may not bake linked-node data into the application package.
4. macOS and Linux never use the AI Board as a substitute native build environment. They require a matching same-SHA native artifact, or source built in the correct native build environment outside the Router VPN production host.
5. Android and iOS/iPadOS never use a Linux-host/router-local mobile build fallback. Their download fails closed until a matching same-SHA mobile artifact exists.

## Platform mapping

- Windows x64/ARM64 installed and Portable packages: release-candidate generic artifact, then matching same-SHA desktop/native CI artifact, then the bounded Windows/Portable-only router-local fallback if both matching artifact sources are unavailable. Packages launch the native WPF Router VPN app; they do not launch Edge/Chrome or embed a browser app.
- macOS x64/ARM64: matching release-candidate artifact, then same-SHA native macOS CI artifact. The selected archive contains the native AppKit/MapKit `RouterVPN.app`. There is no AI Board/router-local substitute for a native macOS build.
- Linux x64/ARM64: architecture-specific release-candidate artifact, then same-SHA native Linux CI artifact. The selected archive contains the native GTK app. There is no AI Board/router-local substitute for a native Linux build.
- Android: matching `RouterVPN-Android-release-candidate`, then same-SHA Android CI artifact. The APK is the native `VpnService` product. No router-local build is allowed.
- iOS/iPadOS: matching `RouterVPN-iOS-release-candidate`, then same-SHA native iOS CI artifact. The artifact is the unsigned re-signable SwiftUI app + PacketTunnel IPA built with the pinned WireGuardKit path and supported pinned Libbox bridge. A legacy authenticated preview-named alias may remain for backward compatibility, but current product UI must not describe the native app as a preview stub. No router-local build is allowed.

## Security and retention

Artifact ZIP extraction is bounded by member count, member size, total size, compression ratio, safe relative paths, and symlink/device rejection. Generic package validation rejects linked router profiles, generated per-node material, private bundles and missing MIT license material. Temporary request/build files are private and removed after delivery/cancellation. CI application artifacts use short retention.

Private node data is linked/imported/paired separately after generic app installation. The authenticated broker never turns private Router VPN control ports public and never uses a floating `latest` release URL as an authoritative package source.

## Release boundary

Same-SHA artifact selection proves package/source provenance, not physical VPN behavior. Real-device permission/routing/DNS/IPv4/IPv6, leak-negative, reconnect, external-exit and Apple signing tests remain separate release gates as documented in `docs/CURRENT-STATUS.md`.
