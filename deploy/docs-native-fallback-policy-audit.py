#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

required = {
    "README.md": (
        "Router-local client fallback is **Windows/Portable only**",
        "macOS and Linux require matching same-SHA artifacts",
        "Android and iOS/iPadOS never use router-local builds",
    ),
    "WHAT-IS-IN-ZIP.md": (
        "only for Windows x64/ARM64 installed/Portable",
        "AI Board never substitutes for those native build environments",
        "Android and iOS/iPadOS never use router-local builds",
    ),
    "docs/INSTALL-PORTAINER.md": (
        "Windows x64/ARM64 installed/Portable",
        "AI Board never substitutes for those native environments",
        "Android and iOS/iPadOS never use router-local builds",
    ),
    "docs/CURRENT-GUIDE.md": (
        "Router-local client fallback is **Windows/Portable only**",
        "AI Board as a substitute native build environment",
        "Android and iOS/iPadOS never use router-local builds",
    ),
    "docs/CURRENT-STATUS.md": (
        "Windows x64/ARM64 installed/Portable only",
        "AI Board as a substitute native build environment",
        "router-local fallback is bounded to the requested generic **Windows/Portable** package",
    ),
    "docs/NATIVE-DOWNLOAD-POLICY.md": (
        "Windows x64/ARM64 installed and Portable requests only",
        "macOS and Linux never use the AI Board as a substitute native build environment",
        "Android and iOS/iPadOS never use a Linux-host/router-local mobile build fallback",
    ),
}

for rel, markers in required.items():
    text = (ROOT / rel).read_text(encoding="utf-8")
    for marker in markers:
        assert marker in text, f"{rel}: missing native fallback truth marker {marker!r}"

for rel in required:
    text = (ROOT / rel).read_text(encoding="utf-8")
    for stale in (
        "AI Board can compile only that requested generic client package",
        "bounded router-local build of the requested generic desktop/Portable package",
        "For desktop/Portable requests only",
        "bounded local build of requested generic client package only",
    ):
        assert stale not in text, f"{rel}: stale over-broad router-local fallback claim returned: {stale!r}"

print("Native fallback documentation policy audit: PASS")
