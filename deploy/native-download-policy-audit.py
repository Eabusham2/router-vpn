#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def text(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        errors.append(f"missing {rel}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def need(rel: str, *markers: str) -> None:
    body = text(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing native-download marker {marker!r}")


def forbid(rel: str, *markers: str) -> None:
    body = text(rel)
    for marker in markers:
        if marker in body:
            errors.append(f"{rel}: forbidden floating/unsafe native-download marker {marker!r}")


def load(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        errors.append(f"cannot load {rel}")
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load("routervpn_native_download_builder_audit", "server/scripts/build-download-on-demand.py")
policy = load("routervpn_native_artifact_policy_audit", "server/scripts/native_artifact_policy.py")
if builder is not None and policy is not None:
    expected = {name: spec[0] for name, spec in builder.PACKAGE_MAP.items() if spec[1] != "bundle"}
    if set(policy.NATIVE_PACKAGE_ARTIFACTS) != set(expected):
        errors.append("native artifact policy does not cover every desktop/Portable public request exactly")
    for request, member in expected.items():
        sources = policy.NATIVE_PACKAGE_ARTIFACTS.get(request, ())
        if len(sources) < 2:
            errors.append(f"{request}: requires release-candidate + CI artifact sources")
            continue
        if sources[0][1] != member:
            errors.append(f"{request}: first source member {sources[0][1]!r} != PACKAGE_MAP {member!r}")
        if not str(sources[0][0]).endswith("release-candidate"):
            errors.append(f"{request}: same-SHA release-candidate artifact is not first")

    for arch in ("amd64", "arm64"):
        mac = policy.NATIVE_PACKAGE_ARTIFACTS.get(f"router-vpn-macos-{arch}.zip", ())
        linux = policy.NATIVE_PACKAGE_ARTIFACTS.get(f"router-vpn-linux-{arch}.zip", ())
        if mac[:2] != (
            ("RouterVPN-macOS-release-candidate", f"RouterVPN-darwin-{arch}.tar.gz"),
            ("RouterVPN-macOS-Native-CI", f"RouterVPN-darwin-{arch}.tar.gz"),
        ):
            errors.append(f"macOS {arch}: native AppKit artifact ordering is wrong")
        if linux[:2] != (
            (f"RouterVPN-Linux-{arch}-release-candidate", f"RouterVPN-linux-{arch}.tar.gz"),
            (f"RouterVPN-Linux-Native-{arch}-CI", f"RouterVPN-linux-{arch}.tar.gz"),
        ):
            errors.append(f"Linux {arch}: native GTK artifact ordering is wrong")

    ios = policy.DIRECT_ARTIFACTS.get("router-vpn-ios.ipa", {}).get("sources", ())
    if ios[:2] != (
        ("RouterVPN-iOS-release-candidate", "RouterVPN-native-unsigned-resignable.ipa"),
        ("RouterVPN-iOS-Native-CI", "RouterVPN-native-unsigned-resignable.ipa"),
    ):
        errors.append("iOS direct download does not prefer the real native WireGuard + Libbox PacketTunnel artifacts")
    if policy.DIRECT_ARTIFACTS.get("router-vpn-ios-preview.ipa", {}).get("sources") != ios:
        errors.append("legacy iOS preview URL must be a compatibility alias to the native IPA")
    android = policy.DIRECT_ARTIFACTS.get("router-vpn-android.apk", {}).get("sources", ())
    if not android or android[0] != ("RouterVPN-Android-release-candidate", "app-debug.apk"):
        errors.append("Android direct download does not prefer the same-SHA release-candidate APK")

need(
    "server/scripts/download-broker.py",
    "native_artifact_policy.py",
    "NATIVE_PACKAGE_ARTIFACTS",
    "_fetch_first_artifact",
    "def _desktop_github_sources",
    "NATIVE_PACKAGE_ARTIFACTS.get(",
    'spec["sources"]',
    "ROUTER_VPN_GITHUB_SHA",
)
need(
    "server/scripts/publish-downloads.sh",
    "iOS/iPadOS native WireGuard IPA",
    "router-vpn-ios.ipa",
    "same-SHA native GitHub artifacts only",
    "Windows x64/ARM64 installed/Portable",
    "windows-portable-amd64",
    "macOS/Linux require a real same-SHA native artifact",
)
for stale in (
    "Desktop/Portable: matching same-SHA",
    "\"local_build_platforms\": \"go-desktop-portable\"",
    "'local_build_platforms':'go-desktop-portable'",
):
    if stale in text("server/scripts/publish-downloads.sh"):
        errors.append(f"publish-downloads contains stale broad router-local fallback claim {stale!r}")
need(
    ".github/workflows/release-candidate.yml",
    "RouterVPN-release-candidate-${{ github.sha }}",
    "RouterVPN-darwin-amd64.tar.gz",
    "RouterVPN-darwin-arm64.tar.gz",
    "RouterVPN-linux-${{ matrix.arch }}.tar.gz",
    "RouterVPN-Windows-$arch.zip",
    "retention-days: 1",
)

broker = text("server/scripts/download-broker.py")
if '"local_build_platforms": ["windows-amd64", "windows-arm64", "windows-portable-amd64", "windows-portable-arm64"]' not in broker:
    errors.append("download broker API does not expose the bounded Windows-only local fallback contract")
if '"local_build_platforms": "go-desktop-portable"' in broker:
    errors.append("download broker API still advertises retired broad go-desktop-portable fallback")
try:
    example = __import__('json').loads(text("configs/client/routers.json.example"))
    if example != {"schema_version": 4, "selected_id": "", "profiles": []}:
        errors.append("routers.json.example is not the blank schema-v4 router store")
except Exception as exc:
    errors.append(f"routers.json.example is not valid JSON: {exc}")
for floating in ("latest.zip", "/releases/latest", "refs/heads/main"):
    if floating in broker:
        errors.append(f"download broker contains floating artifact source {floating!r}")

builder_text = text("server/scripts/build-download-on-demand.py")
for marker in (
    "LOCAL_BUILD_TIMEOUT",
    "compile_requested",
    "same-image prebuilt components",
    "same-SHA native GitHub artifact is required",
    "RouterVPN-{arch}.exe",
    "materialize_icons",
    "controller-only substitute",
    "safe_extract_zip",
    "safe_extract_tar",
):
    if marker not in builder_text:
        errors.append(f"router-local fallback contract missing {marker!r}")

need(
    "server/init/Dockerfile",
    "FROM golang:1.24.13-alpine AS binaries",
    "FROM golang:1.24.13-bookworm AS go-toolchain",
    'dist/RouterVPN-${arch}.exe',
    "prebuilt components",
    "native AppKit/GTK SDK environments are intentionally not installed here",
)
forbid(
    "server/init/Dockerfile",
    "FROM golang:1.24-alpine AS binaries",
    "FROM golang:1.24-bookworm AS go-toolchain",
)

fallback_test = subprocess.run(
    [sys.executable, str(ROOT / "deploy" / "test-router-local-package-fallback.py")],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    check=False,
    timeout=30,
)
if fallback_test.returncode != 0:
    errors.append("router-local complete-package fallback behavior test failed: " + (fallback_test.stdout or "").strip()[-4000:])

scanner = text("deploy/check-generic-package-secrets.py")
for marker in ("generic package contains private bundle", "generic package contains linked router profiles", "package does not ship LICENSE"):
    if marker not in scanner:
        errors.append(f"generic package leak scanner missing {marker!r}")

need(
    "client/install-xray.sh",
    "VERSION=v26.7.11",
    "EXPECTED_SHA256=",
    "Xray archive checksum mismatch",
    "p.is_absolute()",
    '".." in p.parts',
    "stat.S_ISLNK",
    "max_archive",
    "max_members",
    "max_total",
    "zf.open(binary",
)
forbid("client/install-xray.sh", "releases/latest", "extractall(", "extract(")

need(
    "client/install-macos-complete.sh",
    "VERSION=1.13.12",
    "43eef86f0ea4a79c3696974f397a963c46a457ee46d1ffac9aa913944a5fc986",
    "f3275316451bf1983bc059599c69c8ed0232d53a619d15cfd535f95cc9a4477a",
    "shasum -a 256",
    "tar -tzf",
)
forbid("client/install-macos-complete.sh", "curl -fsSL", "| tar -xz")

need(
    "client/install-macos.sh",
    "00569eb273016a10d2e75e5142236f06f7c3d4b3",
    "0527dfa47639714dd8f5c9ffbd9d40d19083f0ba",
    "05434cab7d91bbbc607d18ec5fade91f4b83774c",
    "e9af1cdd2549d528deb20a4ab8d61c5fbe51f306",
    '"$BUNDLE/modes/native-multihop-darwin.sh"',
)
forbid("client/install-macos.sh", "git checkout 00569eb ", "--branch v3.0.2", '"$BUNDLE/client/native-multihop-darwin.sh"')

need(
    "client/install-linux.sh",
    "1ffa3b48ad6fa98f9fd810482e39bdd5b6157782ef11ce37d67bdcfd9338547a",
    "1540533adb3df24f5ad5f14b5c7ca3dbc2401b10a1c1eb278fcadcada47ec6c4",
    "00569eb273016a10d2e75e5142236f06f7c3d4b3",
    "0527dfa47639714dd8f5c9ffbd9d40d19083f0ba",
    "05434cab7d91bbbc607d18ec5fade91f4b83774c",
    "e9af1cdd2549d528deb20a4ab8d61c5fbe51f306",
    "sha256sum",
)
forbid("client/install-linux.sh", "git checkout 00569eb ", "--branch v3.0.2", "curl -fsSL")

need(
    "server/awg2/Dockerfile",
    "AWG_GO_COMMIT=0527dfa47639714dd8f5c9ffbd9d40d19083f0ba",
    "AWGTOOLS_COMMIT=5e882890fbca2316f8ca40e992789d24f67f0118",
)
forbid("server/awg2/Dockerfile", "AWG_GO_TAG=", "AWGTOOLS_TAG=", "refs/tags/${AWG")
need(
    "server/rosenpass/Dockerfile",
    "AWGTOOLS_COMMIT=5e882890fbca2316f8ca40e992789d24f67f0118",
)
forbid("server/rosenpass/Dockerfile", "AWGTOOLS_TAG=", "refs/tags/${AWG")
need("server/aux-proxies/Dockerfile", "SSR_COMMIT=227127c4bc5a6555e0556693d084c96860e75b5e")
forbid("server/aux-proxies/Dockerfile", "SSR_TAG=", '--branch "${SSR_TAG}"')

need(
    "modes/cleanup-private-runtime.py",
    'ALLOWED_ROOTS = {"multihop", "native-multihop", "native-standard-exit", "openvpn-standard-exit"}',
    'relative_to(run_root)',
    'O_NOFOLLOW',
    'follow_symlinks=False',
    'os.path.samestat',
    'os.rename(leaf, quarantine, src_dir_fd=parent_fd, dst_dir_fd=run_fd)',
    'remove_tree_at(run_fd, quarantine)',
)
need("modes/run-multihop.sh", "cleanup-private-runtime.py")
forbid("modes/run-multihop.sh", 'rm -rf "$RUN"')
need("modes/native-multihop-darwin.sh", "cleanup-private-runtime.py", "release_guard")
need("client/native-multihop-windows.ps1", "Remove-PrivateRuntime", "[IO.Directory]::Delete($RuntimeDir,$true)")

if errors:
    print("NATIVE DOWNLOAD POLICY AUDIT: FAIL", file=sys.stderr)
    for err in errors:
        print(" - " + err, file=sys.stderr)
    raise SystemExit(1)
print("NATIVE DOWNLOAD POLICY AUDIT: PASS")
