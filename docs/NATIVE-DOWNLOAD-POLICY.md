# Router VPN native download policy

Router VPN installation packages are generic and contain no linked home/server node. Installing an app and linking Router VPN nodes are separate operations.

## Source order

For every authenticated Setup Center package request, the broker scopes GitHub artifacts to the configured repository, branch and, for release downloads, exact full `ROUTER_VPN_GITHUB_SHA`.

1. Prefer the immutable exact-SHA GitHub Release asset, with matching release target, embedded package provenance and SHA-256 digest.
2. If that asset is unavailable, use a matching same-SHA GitHub Actions artifact from its mapped producer in the manual Router VPN Release workflow.
3. For **Windows x64/ARM64 installed and Portable requests only**, if no same-SHA GitHub package is available, the home node may run the bounded requested-package-only generic Windows fallback using the approved same-image prebuilt components. This fallback may not bake linked-node data into the application package.
4. macOS and Linux never use the AI Board as a substitute native build environment. They require a matching same-SHA native artifact, or source built in the correct native build environment outside the Router VPN production host.
5. Android and iOS/iPadOS never use a Linux-host/router-local mobile build fallback. Their download fails closed until a matching same-SHA mobile artifact exists.

## Platform mapping

- Windows x64/ARM64 installed and Portable packages: exact-SHA Release asset, then matching same-SHA Actions artifact, then the bounded Windows/Portable-only router-local fallback if both matching GitHub sources are unavailable. Packages launch the native WPF Router VPN app.
- macOS x64/ARM64: exact-SHA Release asset, then matching same-SHA Actions artifact. The selected archive contains the native AppKit/MapKit `RouterVPN.app`. There is no AI Board/router-local substitute for a native macOS build.
- Linux x64/ARM64: exact-SHA Release asset, then matching same-SHA Actions artifact. The selected archive contains the native GTK app. There is no AI Board/router-local substitute for a native Linux build.
- Android: exact-SHA Release asset, then matching same-SHA Actions artifact. The APK is the native `VpnService` product. No router-local build is allowed.
- iOS/iPadOS: exact-SHA Release asset, then matching same-SHA Actions artifact. The artifact is the unsigned re-signable SwiftUI app + PacketTunnel IPA built with the pinned WireGuardKit path and supported pinned Libbox bridge. A legacy authenticated preview-named alias may remain for backward compatibility, but current product UI must not describe the native app as a preview stub. No router-local build is allowed.

## Security and retention

Artifact ZIP extraction is bounded by member count, member size, total size, compression ratio, safe relative paths, and symlink/device rejection. Generic package validation rejects linked router profiles, generated per-node material, private bundles and missing MIT license material. Temporary package and build files are private. A completed package and its owned workspace remain available for 30 minutes from READY, including after successful or interrupted delivery. Re-download does not extend the deadline. Cancel, Delete now and shutdown clean them immediately; expiry removes them at the original deadline. Cleanup failures remain visible and are retried. Actions artifact retention is separate from this request lifetime.

Private node data is linked/imported/paired separately after generic app installation. The authenticated broker never turns private Router VPN control ports public and never uses a floating `latest` release URL as an authoritative package source.

## Release boundary

Same-SHA artifact selection proves package/source provenance, not physical VPN behavior. Real-device permission/routing/DNS/IPv4/IPv6, leak-negative, reconnect, external-exit and Apple signing tests remain separate release gates as documented in `docs/CURRENT-STATUS.md`.
