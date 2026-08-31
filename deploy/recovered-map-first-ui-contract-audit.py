#!/usr/bin/env python3
"""Fail-closed source/shipping audit for the recovered native map-first UI contract.

This audit deliberately checks shipping composition rather than accepting an
orphaned source file as implementation.  It is source evidence only; native
build, artifact, rendered-device, path-proof, and production evidence remain
separate release gates.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".inc",
    ".java",
    ".kt",
    ".m",
    ".mm",
    ".ps1",
    ".py",
    ".sh",
    ".swift",
    ".xml",
}


@dataclass(frozen=True)
class Platform:
    name: str
    roots: tuple[str, ...]
    shipping_names: tuple[str, ...]
    native_markers: tuple[str, ...]


PLATFORMS: tuple[Platform, ...] = (
    Platform(
        "Windows",
        ("client",),
        ("routervpn-windows-app.ps1", "routervpn-windows-product-v2.ps1"),
        ("wpf", "system.windows", "window"),
    ),
    Platform(
        "macOS",
        ("client/macos",),
        ("build-native-app.sh", "routervpnmacunifiedshell.swift"),
        ("appkit", "mapkit", "nswindow"),
    ),
    Platform(
        "Linux",
        ("client/linux",),
        ("build-native-app.sh", "routervpn-gtk-product.c"),
        ("gtk", "cairo"),
    ),
    Platform(
        "Android",
        ("android",),
        ("productactivity.java", "androidmanifest.xml"),
        ("activity", "vpnservice", "view"),
    ),
    Platform(
        "iOS/iPadOS",
        ("ios/RouterVPN",),
        ("iosunifiedproductview.swift", "packettunnelprovider.swift"),
        ("swiftui", "mapkit", "networkextension"),
    ),
)

CORE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("map/globe first", ("map", "globe")),
    ("Connect", ("connect",)),
    ("Disconnect", ("disconnect",)),
    ("Fastest", ("fastest",)),
    ("Kill Switch", ("kill switch", "killswitch")),
    ("Multihop", ("multihop", "multi-hop")),
    ("Settings", ("settings",)),
    ("Mode", ("mode",)),
    ("DNS", ("dns",)),
    ("SMART AUTO", ("smart auto", "smart_auto", "smart-auto")),
    ("AUTO", ("auto",)),
    ("CUSTOM", ("custom",)),
    ("Connection Profiles", ("connection profile", "connection-profile")),
    ("live latency", ("latency", "rtt")),
    ("real speed", ("speed test", "speed-test", "mbps")),
)

TRUTH_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("transition/session mutation guard", ("transition", "isbusy", "session mutation", "mutationguard")),
    ("selected/running path identity", ("selected node", "routerid", "session id", "path identity")),
    ("real coordinate handling", ("coordinate", "latitude", "longitude", "location")),
    ("public-exit proof", ("public exit", "publicip", "exit proof")),
)

DEFAULT_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("IPv6 default", ("ipv6",)),
    ("Auto MTU", ("auto mtu", "mtu auto", "mtupolicy")),
    ("AUTO encrypted requirement", ("require encrypted", "auto require encrypted")),
    ("AUTO obfuscation requirement", ("require obfuscation", "auto require obfuscation")),
)

PROFILE_CRUD: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("profile Add", ("profile add", "add profile", "/setup/save", "/connection-profile/setup/save")),
    ("profile Load", ("profile load", "load profile", "/setup/load", "/connection-profile/setup/load")),
    ("profile Update", ("profile update", "update profile", "/setup/update", "/connection-profile/setup/update")),
    ("profile Delete", ("profile delete", "delete profile", "/setup/delete", "/connection-profile/setup/delete")),
)

RETIRED_SHIPPING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Electron", re.compile(r"\belectron\b", re.IGNORECASE)),
    ("WebView final product", re.compile(r"\b(webview|wkwebview)\b", re.IGNORECASE)),
    ("WSL dataplane/UI", re.compile(r"\bwsl(?:\.exe)?\b", re.IGNORECASE)),
    ("PWA final product", re.compile(r"\b(serviceworker|manifest\.webmanifest|progressive web app)\b", re.IGNORECASE)),
)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"cannot read {path.relative_to(ROOT)}: {exc}") from exc


def collect_files(platform: Platform) -> list[Path]:
    files: set[Path] = set()
    for rel_root in platform.roots:
        root = ROOT / rel_root
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
                files.add(path)
    return sorted(files)


def contains_any(text: str, needles: Sequence[str]) -> bool:
    lowered = text.lower()
    return any(needle.lower() in lowered for needle in needles)


def matching_files(files: Iterable[Path], needles: Sequence[str]) -> list[Path]:
    return [path for path in files if contains_any(read_text(path), needles)]


def shipping_files(platform: Platform, files: Sequence[Path]) -> list[Path]:
    wanted = {name.lower() for name in platform.shipping_names}
    found = [path for path in files if path.name.lower() in wanted]
    return sorted(set(found))


def shipping_closure(platform: Platform, files: Sequence[Path]) -> tuple[list[Path], str]:
    """Return conservative shipping entrypoints plus their directly named sources.

    Native builders/launchers often compose generated or transformed sources.  A
    platform contract is accepted only when its shipping entrypoint exists and
    the entrypoint or a source it explicitly names carries the marker.
    """

    entries = shipping_files(platform, files)
    if not entries:
        return [], ""

    by_name: dict[str, list[Path]] = {}
    for path in files:
        by_name.setdefault(path.name.lower(), []).append(path)

    closure: set[Path] = set(entries)
    pending = list(entries)
    while pending:
        current = pending.pop()
        text = read_text(current).lower()
        for name, candidates in by_name.items():
            if name in text:
                for candidate in candidates:
                    if candidate not in closure:
                        closure.add(candidate)
                        pending.append(candidate)
    ordered = sorted(closure)
    return ordered, "\n".join(read_text(path) for path in ordered)


def require_group(
    failures: list[str], platform: Platform, scope: str, label: str, needles: Sequence[str]
) -> None:
    if not contains_any(scope, needles):
        failures.append(f"{platform.name}: shipping closure missing {label}")


def audit_platform(platform: Platform) -> list[str]:
    failures: list[str] = []
    files = collect_files(platform)
    if not files:
        return [f"{platform.name}: native source root missing or empty"]

    closure, scope = shipping_closure(platform, files)
    if not closure:
        expected = ", ".join(platform.shipping_names)
        return [f"{platform.name}: shipping entrypoint missing ({expected})"]

    if not contains_any(scope, platform.native_markers):
        failures.append(f"{platform.name}: shipping closure lacks native-platform markers")

    for label, needles in CORE_GROUPS:
        require_group(failures, platform, scope, label, needles)
    for label, needles in TRUTH_GROUPS:
        require_group(failures, platform, scope, label, needles)
    for label, needles in DEFAULT_GROUPS:
        require_group(failures, platform, scope, label, needles)
    for label, needles in PROFILE_CRUD:
        require_group(failures, platform, scope, label, needles)

    # The audit is intentionally limited to shipping closure, not the whole
    # platform tree, so historical docs/tests may still name rejected designs.
    for label, pattern in RETIRED_SHIPPING_PATTERNS:
        if pattern.search(scope):
            failures.append(f"{platform.name}: shipping closure still references retired {label}")

    return failures


def audit_shared_truth() -> list[str]:
    failures: list[str] = []
    client = ROOT / "cmd/client"
    if not client.is_dir():
        return ["shared controller source cmd/client is missing"]

    files = [
        path
        for path in client.rglob("*")
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES
    ]
    scope = "\n".join(read_text(path) for path in sorted(files))
    required = (
        ("connection operation ownership", ("beginconnectionoperation", "connection operation")),
        ("mutation operation ownership", ("beginmutationoperation", "mutation operation")),
        ("node-bound operation ownership", ("beginnodeboundoperation", "node-bound operation")),
        ("MTU deferred adoption", ("mtu retest", "mtu_retest")),
        ("Fastest transaction", ("fastest",)),
        ("DNS transaction", ("dns retest", "dns_retest", "dns policy")),
        ("profile transaction", ("connection profile", "connection-profile")),
    )
    for label, needles in required:
        if not contains_any(scope, needles):
            failures.append(f"shared controller: missing {label}")
    return failures


def main() -> int:
    failures: list[str] = []
    for platform in PLATFORMS:
        failures.extend(audit_platform(platform))
    failures.extend(audit_shared_truth())

    if failures:
        print("RECOVERED MAP-FIRST UI CONTRACT: FAIL")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("RECOVERED MAP-FIRST UI CONTRACT: PASS")
    print("Source/shipping composition only; native artifact and rendered-device proof remain required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
