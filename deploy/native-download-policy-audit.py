#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
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
        ("RouterVPN-iOS-release-candidate", "RouterVPN-native-wg-unsigned-resignable.ipa"),
        ("RouterVPN-iOS-Native-WireGuard-CI", "RouterVPN-native-wg-unsigned-resignable.ipa"),
    ):
        errors.append("iOS direct download does not prefer the real native WireGuard PacketTunnel artifacts")
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
    "NATIVE_PACKAGE_ARTIFACTS.get(home_name",
    'spec["sources"]',
    "ROUTER_VPN_GITHUB_SHA",
)
need(
    "server/scripts/publish-downloads.sh",
    "iOS/iPadOS native WireGuard IPA",
    "router-vpn-ios.ipa",
    "same-SHA native GitHub artifact only",
)
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
for forbidden in ("latest.zip", "/releases/latest", "refs/heads/main"):
    if forbidden in broker:
        errors.append(f"download broker contains floating artifact source {forbidden!r}")

builder_text = text("server/scripts/build-download-on-demand.py")
for marker in ("LOCAL_BUILD_TIMEOUT", "compile_requested", "may compile only the requested generic Go package", "safe_extract_zip", "safe_extract_tar"):
    if marker not in builder_text:
        errors.append(f"router-local fallback contract missing {marker!r}")

scanner = text("deploy/check-generic-package-secrets.py")
for marker in ("generic package contains private bundle", "generic package contains linked router profiles", "package does not ship LICENSE"):
    if marker not in scanner:
        errors.append(f"generic package leak scanner missing {marker!r}")

if errors:
    print("NATIVE DOWNLOAD POLICY AUDIT: FAIL", file=sys.stderr)
    for err in errors:
        print(" - " + err, file=sys.stderr)
    raise SystemExit(1)
print("NATIVE DOWNLOAD POLICY AUDIT: PASS")
