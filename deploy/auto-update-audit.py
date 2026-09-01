#!/usr/bin/env python3
"""Authoritative exact-SHA auto-update contract for server and native apps."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def text(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def need(rel: str, *markers: str) -> None:
    body = text(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing {marker!r}")


def forbid(rel: str, *markers: str) -> None:
    body = text(rel).lower()
    for marker in markers:
        if marker.lower() in body:
            errors.append(f"{rel}: forbidden {marker!r}")


def absent(rel: str) -> None:
    if (ROOT / rel).exists():
        errors.append(f"obsolete duplicate remains: {rel}")


need(
    "cmd/update-auto/main.go",
    'defaultControllerURL = "http://127.0.0.1:8793"',
    '"/api/admin/update/check"',
    '"/api/admin/update/apply"',
    'status.State.Status == "failed"',
    "readPrivateToken",
)
need(
    "deploy/update-controller.Dockerfile",
    "cmd/update-controller",
    "cmd/update-auto",
    "router-vpn-update-entrypoint",
)
need(
    "deploy/update-controller-entrypoint.sh",
    "router-vpn-update-controller",
    "router-vpn-update-auto",
)
need(
    "server/portainer-current.yaml",
    "ROUTER_VPN_AUTO_UPDATE",
    "ROUTER_VPN_AUTO_UPDATE_INTERVAL",
    "ROUTER_VPN_AUTO_UPDATE_START_DELAY",
)
need(
    "cmd/app-update/main.go",
    'releaseTagPrefix  = "router-vpn-sha-"',
    '"RouterVPN-RELEASE.json"',
    'manifest.Producer != "build-all.yml"',
    "expectedDigest",
    "stageAsset",
    'case "windows":',
    'case "darwin":',
    'case "linux":',
)
forbid("cmd/app-update/main.go", "/releases/latest", "refs/heads/main", "latest.zip")
need(
    "deploy/build-client.sh",
    "cmd/app-update",
    "RouterVPNPortableCore",
    "cmd/portable-bootstrap",
)
need(
    "deploy/package-builds.sh",
    "router-vpn-update.exe",
    "RouterVPNPortableCore.exe",
    "server/scripts/source_provenance.py",
    "write_provenance",
)
need(
    "server/scripts/source_provenance.py",
    "deploy/source_provenance.py",
    "_MODULE._main()",
)
need(
    "deploy/source_provenance.py",
    "ROUTER-VPN-SOURCE.json",
    "source_sha",
    "artifact_family",
)
need(
    "deploy/package-macos-native.sh",
    "./cmd/app-update",
    'sign_macho "$dir/router-vpn-update"',
    "router-vpn-update",
)
need(
    "client/macos/RouterVPNMenuBar.m",
    "Check for Updates",
    "router-vpn-update",
    'arguments = @[@"--download", @"--json"]',
)
need(
    "deploy/package-linux-native.sh",
    "./cmd/app-update",
    "router-vpn-update",
    "Exec=/usr/local/bin/router-vpn",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/RouterVpnUpdateProvider.java",
    "router-vpn-sha-",
    "target_commitish",
    "Android will confirm installation",
)
need(
    "android/app/src/main/AndroidManifest.xml",
    ".RouterVpnUpdateProvider",
    'android:exported="false"',
)
need(
    "ios/RouterVPN/App/IOSUpdateChecker.swift",
    "router-vpn-sha-",
    "target_commitish",
    "never silently replaces its own app bundle",
)
need(
    "ios/RouterVPN/App/RouterVPNApp.swift",
    "checkAutomatically",
    "Router VPN update available",
    "Open exact release",
)

# Signed native-update trust and controller wiring. The legacy packaged helper
# remains the install/staging compatibility path while these routes provide a
# bounded signed-manifest API to every native shell.
need(
    "internal/updatepolicy/manifest.go",
    "ed25519.Verify",
    "DisallowUnknownFields",
    "trailing JSON",
    "moving release URL is forbidden",
    "SelectArtifact",
)
need(
    "internal/updatepolicy/store.go",
    "SaveState",
    "LoadState",
    "InstallPending",
    "LastManifestSHA",
    "update state contains trailing data",
    "update state identity changed during read",
)
need(
    "cmd/client/native_auto_update.go",
    '"/api/update/native/status"',
    '"/api/update/native/check"',
    '"/api/update/native/download"',
    '"X-Router-VPN-Native-App"',
    "ParseAndVerify",
    "DownloadArtifact",
    'json:"source_sha"',
    "mobile updates remain under Android or Apple signed install control",
    "native update manifest redirects are forbidden",
    "LastManifestSHA",
    "rvNativeUpdateMu",
)
need(
    "cmd/client/extras.go",
    "registerNativeUpdateRoutes(h, a)",
)
need(
    "cmd/client/native_auto_update_test.go",
    "TestNativeUpdateCheckAndDownloadRemainSeparate",
    "TestNativeUpdateMutationRequiresLoopbackAppHeader",
    "TestPackagedSourceSHAReadsCanonicalProvenance",
)
need(
    "internal/updatepolicy/manifest_test.go",
    "TestTrailingJSONFailsClosed",
    "TestManifestSignatureCoversArtifacts",
)
absent("cmd/updater/auto_update.go")
absent("cmd/updater/auto_update_test.go")

# Build-all intentionally publishes immutable, fully-gated exact-SHA releases
# as prereleases; every platform checker must accept that exact identity while
# continuing to reject drafts and mismatched targets.
need(".github/workflows/build-all.yml", "--prerelease", 'TAG="router-vpn-sha-${GITHUB_SHA}"')
need("cmd/app-update/main.go", "exactReleaseIdentity", "RouterVPN-RELEASE.json")
forbid("cmd/app-update/main.go", "rel.Draft || rel.Prerelease")
forbid("android/app/src/main/java/com/eabusham/routervpn/RouterVpnUpdateProvider.java", 'release.optBoolean("prerelease")')
forbid("ios/RouterVPN/App/IOSUpdateChecker.swift", 'release["prerelease"]')


# Current exact-SHA staging and release-materialization hardening.
need(
    "internal/updatepolicy/store.go",
    "adoptNoClobber",
    "artifact adoption identity changed",
    "fileMatchesSHA256",
)
need(
    "internal/updatepolicy/store_test.go",
    "TestAdoptNoClobberPreservesConcurrentDestination",
)
need(
    "cmd/app-update/main.go",
    "compareProvesStrictUpgrade",
    "verifyStrictUpgrade",
    "updatepolicy.DownloadArtifact",
    "readSourceManifest",
    "app-update-state.json",
    "persistUpdateResult",
    "notifyStagedUpdate",
    "ArtifactSHA256",
)
need(
    "cmd/app-update/main_test.go",
    "TestCompareProvesStrictUpgrade",
    "TestDecodeReleaseManifestFailsClosed",
    "TestReadSourceManifestRequiresExactRegularFile",
    "TestPersistUpdateResultDeduplicatesNotification",
    "TestPersistUpdateErrorPreservesPendingPackage",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/RouterVpnUpdateProvider.java",
    "RouterVPN-RELEASE.json",
    "strictUpgrade",
    "apk_sha256",
    "producer_workflow",
    "trustedReleaseAssetUrl",
    "Android will confirm installation",
)
need(
    "ios/RouterVPN/App/IOSUpdateChecker.swift",
    "RouterVPN-RELEASE.json",
    "strictUpgrade",
    "validDigest",
    "trustedReleaseURL",
    "Apple/TestFlight/sideload signing remains the installation authority",
)
need(
    "cmd/update-auto/main.go",
    "automatic updates disabled",
    "response contains trailing JSON",
)
need(
    "deploy/materialize-exact-sha-release.py",
    "_adopt_no_clobber",
    "release output adoption identity changed",
)
need(
    "deploy/test_exact_sha_release_materialization.py",
    "concurrent release destination was overwritten",
    "existing metadata destination was overwritten",
)
need(
    "docs/AUTO-UPDATES.md",
    "strict descendant",
    "atomic no-clobber",
    "Android package-signature",
    "never silently replaces its own Apple bundle",
    "rolling-back",
)
need("README.md", "docs/AUTO-UPDATES.md")
need("docs/CURRENT-GUIDE.md", "docs/AUTO-UPDATES.md")
need("docs/NATIVE-APPS.md", "docs/AUTO-UPDATES.md")
need("docs/PRODUCTION-RELEASE.md", "docs/AUTO-UPDATES.md")

if errors:
    print("AUTO UPDATE AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("AUTO UPDATE AUDIT: PASS")
