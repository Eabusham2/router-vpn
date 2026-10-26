# Android signing and upgrade delivery

The authoritative Android job builds a **release variant signed by the configured persistent key** when the complete configuration below is available. Otherwise it builds an explicitly **debug-signed** package. It never generates a production key, treats a debug key as production, or silently falls back after a partial or invalid production configuration.

Set `ROUTERVPN_ANDROID_REQUIRE_PRODUCTION=true` to make missing production configuration a build failure. On non-main refs the authoritative workflow withholds the complete production configuration and performs debug validation. Main keeps the fail-closed behavior for missing required settings, partial settings, invalid passwords, a wrong alias, or a different certificate.

## Configure the persistent identity

Use an existing, securely retained **PKCS12** private-key entry and its public certificate SHA-256 fingerprint. Back up the key and its passwords securely; retain the same signing identity for subsequent updates. This implementation supports one signer and does not implement certificate-rotation lineages.

| GitHub configuration | Type | Purpose |
|---|---|---|
| `ROUTERVPN_ANDROID_KEYSTORE_BASE64` | Actions secret | Base64 encoding of the private PKCS12 keystore; decoded only into a private temporary job directory. |
| `ROUTERVPN_ANDROID_STORE_PASSWORD` | Actions secret | Keystore password. |
| `ROUTERVPN_ANDROID_KEY_ALIAS` | Actions secret | Existing private-key alias. |
| `ROUTERVPN_ANDROID_KEY_PASSWORD` | Actions secret | Private-key password. |
| `ROUTERVPN_ANDROID_CERT_SHA256` | Actions variable | Expected public signing-certificate SHA-256; hexadecimal with optional colons. |
| `ROUTERVPN_ANDROID_REQUIRE_PRODUCTION` | Actions variable | `true` requires production signing on main; absent or `false` permits the labeled debug fallback when **all** signing inputs are absent. |

The build checks the certificate and unlocks the actual private-key entry before selecting release. The final APK must also pass `apksigner verify`, match the pinned certificate, have the expected Android package ID/version, be non-debuggable, and contain the same exact-source and delivery metadata. A configuration-only claim cannot produce the public verification receipt.

For local builds, supply the same environment variables except use `ROUTERVPN_ANDROID_KEYSTORE` with an absolute existing keystore path instead of the base64 input. Keep the key outside the repository, source archives, generic packages, and log output. Supply credentials through the signing environment; do not put their values on the Gradle command line or in tracked files.

From a clean full checkout with the pinned Android SDK/build tools and native-build dependencies installed:

```bash
export ROUTER_VPN_SOURCE_SHA="$(git rev-parse HEAD)"
python3 android/build-delivery.py
```

The wrapper disables Gradle's configuration cache for the credential-bearing delivery invocation and deletes its own decoded CI key on success, failure, or handled cancellation. It leaves an existing local keystore untouched. Only the verified APK and its public receipt are uploaded.

## Version codes and source archives

For an exact commit, `versionCode = 1 + git rev-list --count HEAD`. The entire ancestor set is counted. A strict descendant therefore has a larger code, while rerunning the same commit retains the same code. This starts above the former fixed code `1`. Codes must stay in `2..2100000000`; malformed, overflowing, shallow, wrong-SHA, and modified tracked-source inputs are rejected.

The visible version name is `0.1.<versionCode>-<12-character-source-SHA>`. A development build without exact-source identity is labeled `dev`; it cannot select production signing.

All Android workflow checkouts retain full history. The exact-source snapshot job also captures the code at its verified commit in the public snapshot manifest's `android_version_code` field. The archive itself remains a normal `git archive`, without inventing history inside it. An archive consumer must first verify the requested snapshot/archive through the existing exact-SHA download contract, then supply both its manifest and the **independently requested** SHA:

```bash
python3 android/build-delivery.py \
  --root /verified/router-vpn-source/android \
  --source-manifest /verified/router-vpn-source-manifest.json \
  --source-sha <full-requested-40-character-SHA>
```

The receipt's repository, source family, SHA, and bounded code must match. The runner's unrelated `GITHUB_SHA` is not used to guess an archive's version. An older manifest without a captured code is insufficient; use a verified full checkout instead. Do not fabricate a version pair or copy one from a different source generation.

## Compatibility filename and public evidence

Existing installed clients, Setup Center, provenance checks, and exact-SHA releases request **`app-debug.apk`**. That filename is retained as a compatibility asset name for both delivery variants; it no longer identifies the build type. The actual package is built as `app-release.apk` or `app-debug.apk`, verified, and staged at:

- `android/app/build/outputs/routervpn/app-debug.apk`
- `android/app/build/outputs/routervpn/android-delivery.json`

`assets/ROUTER-VPN-ANDROID.json` inside the APK records its variant, signing state, code, name, source, and pinned production certificate. The public delivery receipt binds the actual APK hash/size and verified signer to those fields. Aggregation and publication reject missing or mismatched receipts. `RouterVPN-RELEASE.json` retains this information in `android_delivery`, and release notes and native download controls display the signing state explicitly. The release still contains ten native packages plus its two manifest/checksum assets.

Setup Center also retains its existing exact-SHA Actions fallback order. `RouterVPN-Android-release-candidate` contains the same configured, verified delivery as the authoritative release. The later `RouterVPN-Android-CI` fallback is **always a debug build**, not production-signed delivery; its debug key is not promised to persist between workflow runs. A generic “Android APK” download label or GitHub provenance alone does not establish production signing or upgrade compatibility. The embedded delivery metadata identifies that fallback as `debug-signed`; the native updater only offers a published-release upgrade when its actual installed certificate and version match the verified release contract.

A direct `assembleRelease` without signing inputs can create an accurately labeled unsigned APK for manual work. Automatic delivery rejects unsigned APKs. Unsigned output is not evidence of installable distribution.

## Existing installations and device acceptance

A new persistent production key **cannot upgrade a same-package APK signed with a different ephemeral debug key**. Increasing the version code does not bypass Android's signing-identity requirement. The native updater compares the published signer and version with the actual installed package through `PackageManager` on Android 24 and later; mismatched signers, non-increasing versions, multiple signers, and unsupported rotation lineages are not offered as compatible upgrades.

Router VPN does not uninstall the existing app, delete its data, or bypass Android's installation confirmation. Any migration from an unrelated key requires an explicit device/data-preservation plan outside this automatic upgrade path.

The CI signing fixture uses a disposable test key and builds small real release/debug/unsigned APKs with the shipping policy. It checks real signature, version, variant, wrong-certificate, and modified-APK behavior. That fixture does **not** establish the availability of the owner's production key or acceptance on an actual device. Production signing configuration, a signed full Router VPN release, and an install/upgrade with the intended persistent identity require their own evidence.

Primary Android contracts: [app signing](https://developer.android.com/studio/publish/app-signing), [versioning](https://developer.android.com/studio/publish/versioning), [SigningInfo](https://developer.android.com/reference/android/content/pm/SigningInfo), and [PackageInfo](https://developer.android.com/reference/android/content/pm/PackageInfo).
