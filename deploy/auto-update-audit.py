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
    "ROUTER-VPN-SOURCE.json",
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

if errors:
    print("AUTO UPDATE AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("AUTO UPDATE AUDIT: PASS")
