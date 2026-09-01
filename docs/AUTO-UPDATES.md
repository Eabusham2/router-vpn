# Router VPN automatic updates

Router VPN uses **exact-source identity**, not a moving `latest` branch or mutable artifact name. Server and app updates have different ownership because replacing a Portainer stack is not the same operation as replacing a running native application.

## Release identity

The authoritative `Build all Router VPN release gates` workflow publishes a gated GitHub prerelease named:

```text
router-vpn-sha-<40-character-source-SHA>
```

The tag and `target_commitish` must equal the same exact SHA. The release includes:

```text
RouterVPN-RELEASE.json
SHA256SUMS
platform packages
```

`RouterVPN-RELEASE.json` records the repository, source SHA, release tag, producer workflow, exact asset sizes and SHA-256 digests. Update consumers reject drafts, malformed/multiple assets, wrong repository/source/tag/producer identity, moving URLs and older/divergent source history.

## Portainer server updates

The production stack contains two private update processes:

```text
router-vpn-update-controller
router-vpn-update-auto
```

The controller is loopback-only at `127.0.0.1:8793`; it does not expose a Docker socket. Portainer credentials and its pinned TLS certificate fingerprint remain server-side. The automatic scheduler reads the private Setup Center token and calls only the controller's authenticated status/check/apply API.

Defaults:

```text
ROUTER_VPN_AUTO_UPDATE=true
ROUTER_VPN_AUTO_UPDATE_START_DELAY=2m
ROUTER_VPN_AUTO_UPDATE_INTERVAL=1h
```

An empty enable setting uses the documented default. A malformed explicit enable setting disables unattended updates rather than silently falling back to `true`. Intervals outside the bounded `5m` to `24h` range fall back to the documented one-hour interval.

Before applying a target, the controller requires one full exact SHA with successful release-candidate, ARM64 image-publication and production-compose evidence. It preserves the current Portainer environment, always uses `Prune=false`, applies core services while the old updater remains available, proves the deployed image set and health, and updates the updater last.

Before the first mutation, the previous exact compose is retained as private rollback state. A failed deployment is not called terminal `failed` until the previous exact stack is restored and health-checked. If rollback cannot complete, durable state remains `rolling-back` so restart reconciliation can retry. Mixed image generations cannot masquerade as one exact SHA.

Setup Center **Release & recovery** displays the same persisted controller state. Browser interruption while Setup Center restarts is expected; the page reconnects and polls rather than treating a broken HTTP request as definitive deployment failure.

## Windows, macOS and Linux apps

Desktop packages ship `router-vpn-update` (or `router-vpn-update.exe`). A native launcher starts a short-lived background check when the app opens.

The helper:

1. reads the package's exact `ROUTER-VPN-SOURCE.json` from one bounded regular non-symlink file;
2. discovers the newest gated exact-SHA prerelease;
3. requires GitHub's compare result to prove that target is a strict descendant of the installed SHA;
4. strictly parses `RouterVPN-RELEASE.json` and verifies repository/source/tag/producer identity;
5. requires exactly one expected platform asset with matching release-API and manifest size;
6. downloads through bounded trusted GitHub release redirects;
7. verifies the complete package size and SHA-256;
8. publishes the staged package with atomic no-clobber semantics;
9. writes private durable `app-update-state.json`; and
10. shows one native notification for a newly staged target.

The helper does **not** replace files underneath a running VPN app. The notification tells the user to close Router VPN and use the staged verified package. Windows uses a native dialog, macOS uses Notification Center, and Linux uses `notify-send` when available. If desktop notification delivery is unavailable, the durable state still records the staged package and exact digest.

Installed and Portable Windows remain separate package types. Portable update staging never converts the product into PortableApps/PAF and must not leave a background process holding the portable folder after exit.

## Android

Android checks at application startup without blocking VPN startup. Before notifying, it requires:

- exact release tag/target identity;
- strict descendant history from the installed source SHA;
- one `RouterVPN-RELEASE.json`;
- one `app-debug.apk` asset;
- manifest schema/repository/source/tag/`build-all.yml` identity; and
- matching APK size plus a valid published SHA-256 digest.

The app stores the exact target, APK URL, size and digest in app-private preferences and opens the trusted GitHub release asset from a notification. Router VPN does not request silent-install authority or bypass Android package-signature and user-confirmation controls.

## iOS and iPadOS

The Apple app performs the equivalent exact tag/target, strict-descendant, release-manifest and IPA size/digest checks. It presents the exact release page only after verification.

Router VPN never silently replaces its own Apple bundle. TestFlight, App Store or explicitly managed sideload signing remains the installation authority. A source-built unsigned/resignable IPA is not represented as a production-signed App Store update.

## Optional signed native-update controller

The loopback client controller also exposes:

```text
GET  /api/update/native/status
POST /api/update/native/check
POST /api/update/native/download
```

POST operations require a loopback request from the native app and the `X-Router-VPN-Native-App: 1` header. This path is enabled only when both an HTTPS signed-manifest URL and a valid base64 Ed25519 public key are configured. It uses a monotonic signed sequence, strict unknown/trailing-JSON rejection, bounded host allowlists, separate check/download phases, private atomic state and verified no-clobber staging.

Mobile download through this controller fails closed; Android and Apple installation remain platform-owned.

## Fail-closed rules

Update discovery or download failure must not interrupt normal VPN startup. However, a malformed trust input is never treated as success. Router VPN rejects:

- moving `/releases/latest`, branch or `latest.zip` fallbacks;
- draft releases;
- target/tag/source mismatches;
- older or divergent histories;
- unknown/trailing signed or release-manifest JSON;
- duplicate, missing, oversized or hash-mismatched assets;
- untrusted redirects;
- symlinked or concurrently replaced provenance/state files;
- concurrent destination replacement during staging; and
- silent mobile or running-app replacement.

An old staged desktop package is not silently reclassified as current after the installed source SHA changes. Exact-current CI/artifact evidence and physical install/network validation remain separate release gates.
