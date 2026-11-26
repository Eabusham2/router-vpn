# Router VPN exact-SHA production release

`server/portainer-current.yaml` is the tracked, image-only production **template/baseline**. It intentionally contains one previously approved exact runtime SHA so the tracked file is reproducible and validates as a real Compose file. It is not proof that its embedded SHA equals a newer source commit.

For a release, the **Materialize exact-head production compose** job in the manual [Router VPN Release workflow](../.github/workflows/build-all.yml) runs `deploy/materialize-production-compose.py` against that template and produces:

```text
RouterVPN-Portainer-<40-character-release-SHA>.yaml
RouterVPN-Portainer-<40-character-release-SHA>.yaml.sha256
```

The materializer changes only Router VPN custom GHCR image tags and `ROUTER_VPN_GITHUB_SHA`. It requires all tracked custom image references and broker provenance to start from one full SHA, preserves pinned third-party images, refuses moving/local-build production constructs, and verifies the generated output is entirely pinned to the requested release SHA.

## Release rule

Use a generated production compose only when all of these are true for the **same SHA**:

1. `main` points at that SHA.
2. `Router VPN CI` and the complete `Router VPN Release` run are green for that SHA.
3. Every `Build and publish ARM64 images` matrix job succeeded for that SHA.
4. The release's `Materialize exact-head production compose` job succeeded for that SHA.
5. The generated compose artifact checksum passes.
6. The generated file's Router VPN image tags and `ROUTER_VPN_GITHUB_SHA` all equal that SHA.
7. `server/scripts/verify-production-compose.py` accepts the generated YAML.

Do not deploy the tracked baseline file merely because it is named `portainer-current.yaml`, and do not deploy an older generated RC after `main` has moved.

## Portainer

For the deliberate release update, use the generated exact-SHA YAML as the Router VPN stack definition and configure the values for your installation, or preserve them during an upgrade. These are examples:

```env
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` remains optional and should normally be unset so endpoint detection can operate. Do not add a moving image tag or `build:` fallback. Do not WAN-forward private/admin ports (`1080`, `8786-8793`, `9443`, `14444`, `45999`, SSH, Portainer, or AdGuard admin).

## Automatic Portainer updates

The generated production stack includes a loopback-only update controller plus an automatic scheduler. The scheduler is enabled by default, waits two minutes after startup and checks hourly unless bounded environment overrides are supplied. A malformed explicit enable setting disables unattended updates.

The controller requires the same exact-SHA release/image/compose preconditions as a deliberate manual release, preserves the existing Portainer environment, keeps `Prune=false`, stores the previous exact compose before mutation, proves core health, updates itself last and restores the previous healthy stack on failure. Failed rollback remains durable `rolling-back` so restart reconciliation can continue; mixed image generations never count as one exact SHA. See `docs/AUTO-UPDATES.md`.

## Terminal manager

The terminal install/upgrade path uses the same generated release contract and rejects the tracked baseline. Example:

```bash
export ROUTER_VPN_PRODUCTION_COMPOSE=/absolute/path/RouterVPN-Portainer-<release-sha>.yaml
sudo -E bash server/manage.sh
```

`server/install.sh` and `server/upgrade.sh` call `server/scripts/verify-production-compose.py` before Docker. The verifier requires the generated exact-SHA header, exact Router VPN custom-image counts/pins, matching broker provenance, no moving Router VPN tag, and no production `build:`/remote Git context.

After the update, prove the one-shot init/finalizer exit cleanly, all expected long-running services stay running, Setup Center `/healthz` returns 200, the running image IDs/tags match the selected SHA, and the selected VPN path itself passes the separate live release matrix before calling the whole release complete.


---

<a id="section-exact-sha-download-delivery"></a>

# Router VPN exact-SHA download delivery

Router VPN uses one immutable source identity from CI through the private Setup Center.

```text
commit to main
→ successful routine CI and manual release gates for the same commit
→ native packages and server images prove the same full exact source SHA
→ CI publishes the native packages to a prerelease tagged router-vpn-sha-<40-hex SHA>
→ the private Setup Center downloads only that exact-SHA GitHub Release asset
→ validates GitHub's SHA-256 digest and embedded package provenance
→ validates and temporarily repacks only the requested generic package
→ streams it to the authenticated user
→ retains the package and owned workspace until 30 minutes from READY for retry
→ removes them at expiry, or immediately on Cancel, Delete now, or shutdown
```

The release is not `latest`, does not follow a moving branch, and is rejected unless both its tag and `target_commitish` resolve directly to the requested full exact source SHA.

## Ordered delivery sources

For Windows, Windows Portable, macOS, and Linux requests:

1. Immutable exact-SHA GitHub Release asset.
2. Same-SHA GitHub Actions artifact from the mapped producer workflow.
3. Bounded router-local build of only the requested generic desktop/Portable package.

The router-local path builds only a requested generic Windows or Windows Portable package from the approved same-image inputs. It uses the pinned source and keeps private node linking separate from the application package. The package and its owned build workspace remain available for retry until 30 minutes from READY; delivery does not extend the deadline. Cancel, Delete now, shutdown and expiry follow the same cleanup policy as a GitHub-sourced package. macOS and Linux require their native build environments outside the production host.

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


---

<a id="section-current-certification"></a>

# Current exact-head certification

Router VPN accepts GitHub/release completion only when one exact public `main` commit proves all of the following without borrowing evidence from an older SHA:

- reconciled requirements, recovered requirements 1–356 and C1–C7;
- real shipping composition for Windows, macOS, Linux, Android and iOS/iPadOS;
- unified map-first product, session-mutation, profile, durability and fail-open contracts;
- Windows installed and Portable x64/ARM64 packages;
- macOS Intel/Apple Silicon and Linux x64/ARM64 packages;
- Android APK and real iOS `xcodebuild`/IPA;
- ARM64 production images and Portainer preflight;
- one generated image-only production compose whose broker and custom images share the exact SHA;
- immutable exact-SHA prerelease assets, release manifest and SHA-256 checksums.

Setup Center package delivery is exact-SHA GitHub Release first, matching exact-SHA Actions artifact second, and a bounded supported desktop/Portable local build only when GitHub delivery is unavailable. Android and iOS remain artifact-only. A completed package and its owned build workspace remain retryable for 30 minutes from READY; downloading does not extend the deadline; Cancel/Delete/Shutdown removes it immediately.

Physical-device, private AI Board/Portainer, ASUS-router, off-LAN, live-provider and Apple distribution evidence remain separate and may not be inferred from source or CI.


---

<a id="section-exact-head-certification"></a>

# Exact-Head Certification

This file marks the authoritative Router VPN source generation that must be certified as one exact Git commit.

The certification matrix must prove, for the same SHA:

- recovered requirements 1–356 and corrections C1–C7;
- native map-first shipping composition on Windows, macOS, Linux, Android, and iOS/iPadOS;
- backend session/mutation serialization and stale-result rejection;
- private/durable state, endpoint ownership, updater rollback, and ASUS fail-open source contracts;
- Windows installed and Portable x64/ARM64 packages;
- macOS Intel/Apple Silicon and Linux x64/ARM64 packages;
- Android APK and real iOS/iPadOS build/IPA;
- ARM64 production images and exact-SHA Portainer compose;
- aggregate package provenance, checksums, licenses, and secret-free archives.

Setup Center package delivery is exact-SHA GitHub Release first, exact-SHA Actions artifact second, then only a bounded supported local desktop/Portable fallback. Generated local packages and their owned workspaces remain available for retry for 30 minutes from READY and are then deleted; explicit cancel/delete and shutdown clean them immediately. Mobile remains exact-SHA artifact-only.

Physical devices, private production infrastructure, ASUS hardware, off-LAN interoperability, live AI providers, and Apple distribution are separate evidence gates and must never be inferred from CI.
