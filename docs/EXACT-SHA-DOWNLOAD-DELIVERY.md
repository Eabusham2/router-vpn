# Router VPN exact-SHA download delivery

Router VPN uses one immutable source identity from CI through the private Setup Center.

```text
commit to main
→ authoritative build-all CI
→ native packages and server images prove the same full exact source SHA
→ CI publishes the native packages to a prerelease tagged router-vpn-sha-<40-hex SHA>
→ the private Setup Center downloads only that exact-SHA GitHub Release asset
→ validates GitHub's SHA-256 digest and embedded package provenance
→ temporarily repacks/customizes only the requested package
→ streams it to the authenticated user
→ deletes the request workspace after delivery, cancellation, interruption, or expiry
```

The release is not `latest`, does not follow a moving branch, and is rejected unless both its tag and `target_commitish` resolve directly to the requested full exact source SHA.

## Ordered delivery sources

For Windows, Windows Portable, macOS, and Linux requests:

1. Immutable exact-SHA GitHub Release asset.
2. Same-SHA GitHub Actions artifact from the mapped producer workflow.
3. Bounded router-local build of only the requested generic desktop/Portable package.

The router-local path is a fallback, not the normal build farm. It uses the checked-out pinned source, builds one requested package, injects private home/node data only in a temporary request directory, streams the result, and removes the temporary input/output. It never builds every platform at once.

For Android and iOS:

1. Immutable exact-SHA GitHub Release asset.
2. Same-SHA GitHub Actions mobile artifact.
3. No Linux router-local fallback.

Android and iOS remain GitHub-only because the Linux home node cannot truthfully reproduce the Android toolchain, Xcode, NetworkExtension packaging, Apple signing, or IPA provenance. A missing mobile artifact fails closed instead of returning a fake package.

## Release contents

Every exact-SHA prerelease contains these ten native package assets plus `RouterVPN-RELEASE.json` and `SHA256SUMS`:

```text
RouterVPN-Windows-amd64.zip
RouterVPN-Windows-arm64.zip
RouterVPN-Portable-Windows-amd64.zip
RouterVPN-Portable-Windows-arm64.zip
RouterVPN-darwin-amd64.tar.gz
RouterVPN-darwin-arm64.tar.gz
RouterVPN-linux-amd64.tar.gz
RouterVPN-linux-arm64.tar.gz
app-debug.apk
RouterVPN-native-unsigned-resignable.ipa
```

Generic release assets contain no private Router VPN node, WireGuard private key, API token, Setup Center credential, SOCKS password, or home-specific endpoint secret. Private linking remains a separate authenticated bundle/pairing operation.

## Portainer and Setup Center boundary

Portainer pulls exact-SHA server images through the production compose/update controller. The Setup Center serves client downloads from private port `8786`; it does not expose release credentials or private client material to WAN. The Setup Center may use a server-side GitHub token for rate limits/private retrieval, but strips authorization before GitHub's cross-origin blob-storage redirect.

This delivery pipeline does not make source, shipping, CI, artifact, physical runtime, selected-path proof, and production deployment equivalent. Each remains a separate evidence gate.
