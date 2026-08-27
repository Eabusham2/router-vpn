#!/usr/bin/env python3
"""Keep native download policy, shipping workflows, and required build toolchains in lockstep."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    path = ROOT / rel
    assert path.is_file(), f"missing workflow/source: {rel}"
    return path.read_text(encoding="utf-8")


def load_policy():
    path = ROOT / "server/scripts/native_artifact_policy.py"
    spec = importlib.util.spec_from_file_location("routervpn_native_artifact_policy_parity", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(body: str, rel: str, *markers: str) -> None:
    for marker in markers:
        assert marker in body, f"{rel}: missing artifact/toolchain marker {marker!r}"


policy = load_policy()
rc_rel = ".github/workflows/release-candidate.yml"
client_rel = ".github/workflows/client-apps-ci.yml"
mac_rel = ".github/workflows/macos-native-app.yml"
linux_rel = ".github/workflows/linux-native-app.yml"
diag_rel = ".github/workflows/android-diagnostic.yml"
combined_rel = ".github/workflows/android-combined-runtime.yml"
package_rel = "deploy/package-builds.sh"
mac_package_rel = "deploy/package-macos-native.sh"
linux_package_rel = "deploy/package-linux-native.sh"
broker_builder_rel = "server/scripts/build-download-on-demand.py"
provenance_rel = "deploy/source_provenance.py"
provenance_test_rel = "deploy/test_source_provenance.py"
local_fallback_test_rel = "deploy/test-router-local-package-fallback.py"
mobile_provenance_rel = "server/scripts/mobile-artifact-provenance.py"
mobile_provenance_test_rel = "server/scripts/test_mobile_artifact_provenance.py"
broker_exact_sha_test_rel = "server/scripts/test_download_broker_exact_sha.py"
android_gradle_rel = "android/app/build.gradle"
ios_project_rel = "ios/RouterVPN/project.yml"
rc = read(rc_rel)
client = read(client_rel)
mac = read(mac_rel)
linux = read(linux_rel)
diag = read(diag_rel)
combined = read(combined_rel)
package_builds = read(package_rel)
mac_package = read(mac_package_rel)
linux_package = read(linux_package_rel)
broker_builder = read(broker_builder_rel)
provenance = read(provenance_rel)
provenance_test = read(provenance_test_rel)
local_fallback_test = read(local_fallback_test_rel)
mobile_provenance = read(mobile_provenance_rel)
mobile_provenance_test = read(mobile_provenance_test_rel)
broker_exact_sha_test = read(broker_exact_sha_test_rel)
android_gradle = read(android_gradle_rel)
ios_project = read(ios_project_rel)


# A workflow name/head SHA is not enough after an artifact has been downloaded or
# repacked. Every desktop/native archive carries a self-describing full source
# SHA and the authenticated broker re-verifies it against the deployed exact SHA.
require(provenance, provenance_rel,
        "ROUTER-VPN-SOURCE.json",
        "source provenance requires one full 40-character Git commit SHA",
        "os.path.samestat(opened, current)",
        "source provenance mismatch",
        "source provenance repository mismatch")
require(provenance_test, provenance_test_rel,
        "wrong exact source SHA was accepted",
        "missing source repository was silently defaulted",
        "source provenance replacement race was accepted",
        "symlink package root")
require(package_builds, package_rel,
        "source_provenance.py",
        "write_provenance",
        "windows-$arch",
        "windows-portable-$arch")
require(mac_package, mac_package_rel,
        "source_provenance.py",
        'macos-$arch',
        "ROUTER-VPN-SOURCE.json")
require(linux_package, linux_package_rel,
        "source_provenance.py",
        'linux-$ARCH',
        "ROUTER-VPN-SOURCE.json")
require(broker_builder, broker_builder_rel,
        "_provenance.verify_manifest",
        "provenance_family",
        "expected_sha",
        "expected_family")
require(local_fallback_test, local_fallback_test_rel,
        "wrong embedded source SHA was accepted",
        "wrong embedded family was accepted")
require(rc, rc_rel, "python3 deploy/test_source_provenance.py")

# Mobile artifacts are also self-identifying. Android embeds a bounded source
# manifest inside the APK; iOS embeds the exact source identity in both the app
# and PacketTunnel Info.plists. The authenticated broker re-verifies those
# values after artifact extraction and before delivery.
require(mobile_provenance, mobile_provenance_rel,
        "assets/ROUTER-VPN-SOURCE.json",
        "RouterVPNSourceSHA",
        "RouterVPNSourceRepository",
        "ios-packet-tunnel",
        "mobile artifact source SHA mismatch")
require(mobile_provenance_test, mobile_provenance_test_rel,
        "wrong-sha.apk",
        "duplicate-app.ipa",
        "missing-tunnel.ipa",
        "exact_ios_app_and_packet_tunnel_are_both_required")
require(broker_builder, broker_builder_rel, "_provenance.verify_manifest")
broker = read("server/scripts/download-broker.py")
require(broker, "server/scripts/download-broker.py",
        "mobile-artifact-provenance.py",
        "_mobile_provenance.verify(name, selected, head_sha, repo)")
require(broker_exact_sha_test, broker_exact_sha_test_rel,
        "mobile_binary_is_reverified_after_exact_sha_artifact_selection",
        "mobile_binary_provenance_failure_blocks_delivery")
require(android_gradle, android_gradle_rel,
        "ROUTER-VPN-SOURCE.json",
        "artifact_family: 'android-apk'",
        "Android APK source provenance mismatch")
require(ios_project, ios_project_rel,
        "INFOPLIST_KEY_RouterVPNSourceSHA",
        "INFOPLIST_KEY_RouterVPNSourceRepository",
        'INFOPLIST_KEY_RouterVPNArtifactFamily: "ios-app"',
        'INFOPLIST_KEY_RouterVPNArtifactFamily: "ios-packet-tunnel"')
for rel, body in ((rc_rel, rc), (client_rel, client)):
    require(body, rel,
            'ROUTER_VPN_SOURCE_SHA="$GITHUB_SHA"',
            "plutil -extract RouterVPNSourceSHA",
            "RouterVPNArtifactFamily")
require(rc, rc_rel,
        "python3 server/scripts/test_mobile_artifact_provenance.py",
        "python3 server/scripts/test_download_broker_exact_sha.py")

# Every workflow that assembles the full Android APK also executes native AAR
# build tasks; all of them must pin the exact Go toolchain required by libbox.
for rel, body in (
    (rc_rel, rc),
    (client_rel, client),
    (diag_rel, diag),
    (combined_rel, combined),
):
    require(body, rel, ":app:assembleDebug", "actions/setup-go@v5", "go-version: '1.26.3'", "gradle-version: '9.5.0'")

# Release-candidate and dedicated fallback artifacts must use the names/members
# that the authenticated download broker actually asks GitHub for.
require(rc, rc_rel,
        "name: RouterVPN-generic-release-candidate",
        "path: |\n            dist/packages/*",
        "name: RouterVPN-Android-release-candidate",
        "path: android/app/build/outputs/apk/debug/app-debug.apk",
        "name: RouterVPN-iOS-release-candidate",
        "path: ios/RouterVPN/build/RouterVPN-native-unsigned-resignable.ipa",
        "name: RouterVPN-macOS-release-candidate",
        "dist/macos-native/RouterVPN-darwin-amd64.tar.gz",
        "dist/macos-native/RouterVPN-darwin-arm64.tar.gz",
        "name: RouterVPN-Linux-${{ matrix.arch }}-release-candidate",
        "dist/linux-native/RouterVPN-linux-${{ matrix.arch }}.tar.gz",
        "name: RouterVPN-release-candidate-${{ github.sha }}")
require(client, client_rel,
        "name: RouterVPN-client-desktop-unix-ci",
        "dist/packages/*",
        "name: RouterVPN-Android-CI",
        "path: android/app/build/outputs/apk/debug/app-debug.apk",
        "name: RouterVPN-iOS-Native-CI",
        "path: ios/RouterVPN/build/RouterVPN-native-unsigned-resignable.ipa")
require(mac, mac_rel,
        "name: RouterVPN-macOS-Native-CI",
        "dist/macos-native/RouterVPN-darwin-amd64.tar.gz",
        "dist/macos-native/RouterVPN-darwin-arm64.tar.gz")
require(linux, linux_rel,
        "name: RouterVPN-Linux-Native-${{ matrix.arch }}-CI",
        "dist/linux-native/RouterVPN-linux-${{ matrix.arch }}.tar.gz")

# Validate every concrete desktop policy source against its real producer. The
# generic Windows artifact uploads a directory glob, so concrete ZIP membership
# is proven by package-builds.sh rather than by pretending the YAML lists files.
for request, sources in policy.NATIVE_PACKAGE_ARTIFACTS.items():
    assert len(sources) >= 2, f"{request}: missing two-source native artifact policy"
    for artifact, member in sources[:2]:
        if artifact in ("RouterVPN-generic-release-candidate", "RouterVPN-client-desktop-unix-ci"):
            workflow = rc if artifact == "RouterVPN-generic-release-candidate" else client
            assert artifact in workflow, f"{request}: producer workflow does not upload artifact {artifact}"
            arch = "arm64" if "arm64" in member else "amd64"
            rendered = package_builds.replace("$arch", arch)
            base = member[:-4] if member.endswith(".zip") else member
            assert base in rendered, f"{request}: package builder does not produce {member}"
            continue
        if artifact == "RouterVPN-macOS-release-candidate":
            producer = rc
        elif artifact == "RouterVPN-macOS-Native-CI":
            producer = mac
        elif artifact.startswith("RouterVPN-Linux-") and artifact.endswith("-release-candidate"):
            arch = "arm64" if "arm64" in artifact else "amd64"
            producer = rc.replace("${{ matrix.arch }}", arch)
        elif artifact.startswith("RouterVPN-Linux-Native-") and artifact.endswith("-CI"):
            arch = "arm64" if "arm64" in artifact else "amd64"
            producer = linux.replace("${{ matrix.arch }}", arch)
        else:
            raise AssertionError(f"{request}: no workflow mapping for artifact {artifact}")
        assert artifact in producer, f"{request}: producer workflow does not upload artifact {artifact}"
        assert member in producer, f"{request}: producer workflow does not upload member {member}"

# Same for mobile direct-download policy.
for request, spec in policy.DIRECT_ARTIFACTS.items():
    sources = spec.get("sources", ())
    assert sources, f"{request}: direct artifact has no sources"
    # The preview URL intentionally aliases the exact same iOS source tuple.
    for artifact, member in sources:
        if artifact == "RouterVPN-Android-release-candidate": producer = rc
        elif artifact == "RouterVPN-Android-CI": producer = client
        elif artifact == "RouterVPN-iOS-release-candidate": producer = rc
        elif artifact == "RouterVPN-iOS-Native-CI": producer = client
        else: raise AssertionError(f"{request}: no workflow mapping for direct artifact {artifact}")
        assert artifact in producer, f"{request}: producer workflow does not upload artifact {artifact}"
        assert member in producer, f"{request}: producer workflow does not upload member {member}"

# Keep the one-SHA aggregate exhaustive rather than silently dropping a platform.
require(rc, rc_rel,
        "needs: [source-audit, generic-builds, windows-native-smoke, android, ios, macos, linux]",
        "pattern: '*-release-candidate'",
        "RELEASE-CANDIDATE-SHA256SUMS",
        "sha256sum -c RELEASE-CANDIDATE-SHA256SUMS")

# Product-facing mobile source docs must describe the runtimes the native jobs
# actually build, without reviving the retired controller/importer-only shell.
ios_readme = read("ios/README.md")
require(ios_readme, "ios/README.md",
        "native SwiftUI Router VPN application",
        "pinned WireGuardKit adapter",
        "pinned Libbox bridge",
        "RouterVPN-native-unsigned-resignable.ipa",
        "release-candidate.yml",
        "client-apps-ci.yml",
        "Unsupported paths fail closed")
for stale in (
    "SwiftUI controller/importer",
    "native tunnel adapter is missing",
    "custom VPN connections will not work until",
):
    assert stale not in ios_readme, f"ios/README.md: stale pre-native runtime claim returned: {stale!r}"

publisher = read("server/scripts/publish-downloads.sh")
assert "Same-SHA native Android VpnService app" in publisher, "Setup Center publisher reverted Android to a controller/importer label"
assert "Android controller/importer APK" not in publisher, "Setup Center publisher contains retired Android shell wording"

print("native artifact/workflow parity audit: OK")
