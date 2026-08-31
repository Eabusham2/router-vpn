#!/usr/bin/env python3
"""Exact artifact routing for authenticated Router VPN downloads.

Public Setup Center request names stay stable and generic/node-secret-free. Each
request prefers the immutable exact-SHA GitHub Release asset produced by
build-all, then a same-SHA release-candidate Actions artifact, then a same-SHA
dedicated native CI artifact when one exists. Desktop requests may fall back to
the bounded router-local generic builder only after all GitHub sources fail.
Mobile requests never use a Linux-host fake build fallback.
"""
from __future__ import annotations

EXACT_SHA_RELEASE_TAG_PREFIX = "router-vpn-sha-"

# Public authenticated Setup Center request name -> immutable asset name inside
# the exact-SHA GitHub Release. The release tag itself contains the full source
# SHA, so stable member names do not create a moving-main trust boundary.
EXACT_SHA_RELEASE_ASSETS: dict[str, str] = {
    "router-vpn-windows-amd64.zip": "RouterVPN-Windows-amd64.zip",
    "router-vpn-windows-arm64.zip": "RouterVPN-Windows-arm64.zip",
    "router-vpn-windows-portable-amd64.zip": "RouterVPN-Portable-Windows-amd64.zip",
    "router-vpn-windows-portable-arm64.zip": "RouterVPN-Portable-Windows-arm64.zip",
    "router-vpn-macos-amd64.zip": "RouterVPN-darwin-amd64.tar.gz",
    "router-vpn-macos-arm64.zip": "RouterVPN-darwin-arm64.tar.gz",
    "router-vpn-linux-amd64.zip": "RouterVPN-linux-amd64.tar.gz",
    "router-vpn-linux-arm64.zip": "RouterVPN-linux-arm64.tar.gz",
    "router-vpn-android.apk": "app-debug.apk",
    "router-vpn-ios.ipa": "RouterVPN-native-unsigned-resignable.ipa",
    "router-vpn-ios-preview.ipa": "RouterVPN-native-unsigned-resignable.ipa",
}

# request name -> ordered (GitHub Actions artifact name, member filename)
NATIVE_PACKAGE_ARTIFACTS: dict[str, tuple[tuple[str, str], ...]] = {
    "router-vpn-windows-amd64.zip": (
        ("RouterVPN-generic-release-candidate", "RouterVPN-Windows-amd64.zip"),
        ("RouterVPN-client-desktop-unix-ci", "RouterVPN-Windows-amd64.zip"),
    ),
    "router-vpn-windows-arm64.zip": (
        ("RouterVPN-generic-release-candidate", "RouterVPN-Windows-arm64.zip"),
        ("RouterVPN-client-desktop-unix-ci", "RouterVPN-Windows-arm64.zip"),
    ),
    "router-vpn-windows-portable-amd64.zip": (
        ("RouterVPN-generic-release-candidate", "RouterVPN-Portable-Windows-amd64.zip"),
        ("RouterVPN-client-desktop-unix-ci", "RouterVPN-Portable-Windows-amd64.zip"),
    ),
    "router-vpn-windows-portable-arm64.zip": (
        ("RouterVPN-generic-release-candidate", "RouterVPN-Portable-Windows-arm64.zip"),
        ("RouterVPN-client-desktop-unix-ci", "RouterVPN-Portable-Windows-arm64.zip"),
    ),
    "router-vpn-macos-amd64.zip": (
        ("RouterVPN-macOS-release-candidate", "RouterVPN-darwin-amd64.tar.gz"),
        ("RouterVPN-macOS-Native-CI", "RouterVPN-darwin-amd64.tar.gz"),
    ),
    "router-vpn-macos-arm64.zip": (
        ("RouterVPN-macOS-release-candidate", "RouterVPN-darwin-arm64.tar.gz"),
        ("RouterVPN-macOS-Native-CI", "RouterVPN-darwin-arm64.tar.gz"),
    ),
    "router-vpn-linux-amd64.zip": (
        ("RouterVPN-Linux-amd64-release-candidate", "RouterVPN-linux-amd64.tar.gz"),
        ("RouterVPN-Linux-Native-amd64-CI", "RouterVPN-linux-amd64.tar.gz"),
    ),
    "router-vpn-linux-arm64.zip": (
        ("RouterVPN-Linux-arm64-release-candidate", "RouterVPN-linux-arm64.tar.gz"),
        ("RouterVPN-Linux-Native-arm64-CI", "RouterVPN-linux-arm64.tar.gz"),
    ),
}

_ANDROID_SOURCES = (
    ("RouterVPN-Android-release-candidate", "app-debug.apk"),
    ("RouterVPN-Android-CI", "app-debug.apk"),
)
_IOS_SOURCES = (
    ("RouterVPN-iOS-release-candidate", "RouterVPN-native-unsigned-resignable.ipa"),
    ("RouterVPN-iOS-Native-CI", "RouterVPN-native-unsigned-resignable.ipa"),
)

ARTIFACT_PRODUCER_WORKFLOWS: dict[str, str] = {
    "RouterVPN-generic-release-candidate": "build-all.yml",
    "RouterVPN-macOS-release-candidate": "build-all.yml",
    "RouterVPN-Linux-amd64-release-candidate": "build-all.yml",
    "RouterVPN-Linux-arm64-release-candidate": "build-all.yml",
    "RouterVPN-Android-release-candidate": "build-all.yml",
    "RouterVPN-iOS-release-candidate": "build-all.yml",
    "RouterVPN-client-desktop-unix-ci": "client-apps-ci.yml",
    "RouterVPN-Android-CI": "client-apps-ci.yml",
    "RouterVPN-iOS-Native-CI": "client-apps-ci.yml",
    "RouterVPN-macOS-Native-CI": "macos-native-app.yml",
    "RouterVPN-Linux-Native-amd64-CI": "linux-native-app.yml",
    "RouterVPN-Linux-Native-arm64-CI": "linux-native-app.yml",
}


DIRECT_ARTIFACTS: dict[str, dict[str, object]] = {
    "router-vpn-android.apk": {
        "sources": _ANDROID_SOURCES,
        "content_type": "application/vnd.android.package-archive",
    },
    "router-vpn-ios.ipa": {
        "sources": _IOS_SOURCES,
        "content_type": "application/octet-stream",
    },
    # Backward-compatible authenticated URL only. New Setup Center pages use
    # router-vpn-ios.ipa so the UI no longer describes the real PacketTunnel as
    # a preview.
    "router-vpn-ios-preview.ipa": {
        "sources": _IOS_SOURCES,
        "content_type": "application/octet-stream",
    },
}
