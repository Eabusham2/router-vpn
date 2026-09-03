#!/usr/bin/env python3
"""Recovered native Router VPN UI product-contract audit.

This is the cross-platform semantic half of the gate.  It intentionally does
not claim that finding a token proves shipping composition; the companion
release gate also runs the established platform-specific shipping/session
checks.  Native compilation, built-artifact inspection, rendered UI, real path
proof, and physical release evidence remain distinct gates.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".go", ".h", ".inc", ".java", ".kt", ".m", ".mm",
    ".ps1", ".py", ".sh", ".swift", ".xml",
}

PLATFORMS: dict[str, tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "Windows": (
        ("client",),
        ("routervpn-windows-app.ps1", "routervpn-windows-product-v2.ps1"),
        ("wpf", "system.windows"),
    ),
    "macOS": (
        ("client/macos",),
        ("build-native-app.sh", "routervpnmacunifiedshell.swift"),
        ("appkit", "mapkit"),
    ),
    "Linux": (
        ("client/linux",),
        ("build-native-app.sh", "routervpn-gtk-product.c"),
        ("gtk", "cairo"),
    ),
    "Android": (
        ("android",),
        ("productactivity.java", "androidmanifest.xml"),
        ("activity", "vpnservice"),
    ),
    "iOS/iPadOS": (
        ("ios/RouterVPN",),
        ("iosunifiedproductview.swift", "packettunnelprovider.swift"),
        ("swiftui", "mapkit", "networkextension"),
    ),
}

PRODUCT_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("map/globe-first surface", ("map", "globe")),
    ("Connect", ("connect",)),
    ("Disconnect", ("disconnect",)),
    ("Fastest node", ("fastest",)),
    ("live latency", ("latency", "rtt")),
    ("kill switch", ("kill switch", "killswitch")),
    ("Forwarding Master", ("forwarding master", "forward master")),
    ("Multihop", ("multihop", "multi-hop")),
    ("Settings", ("settings",)),
    ("Mode", ("mode",)),
    ("DNS", ("dns",)),
    ("SMART AUTO", ("smart auto", "smart_auto", "smart-auto")),
    ("AUTO", ("auto",)),
    ("CUSTOM", ("custom",)),
    ("Connection Profiles", ("connection profile", "connection-profile")),
    ("real current-path speed", ("speed test", "speed-test", "mbps")),
    ("real coordinates/location", ("coordinate", "latitude", "longitude", "location")),
    ("selected/running path proof", ("public exit", "exit proof", "path identity", "routerid")),
)

SETTINGS_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("IPv6", ("ipv6",)),
    ("LAN policy", ("lan policy", "lan access", "allowlan")),
    ("Auto/Fixed/Retest MTU", ("mtu", "retest")),
    ("AUTO encrypted requirement", ("require encrypted", "auto require encrypted")),
    ("AUTO obfuscation requirement", ("require obfuscation", "auto require obfuscation")),
)

PROFILE_CRUD: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("profile Add", ("add profile", "profile add", "/connection-profile/setup/save")),
    ("profile Load", ("load profile", "profile load", "/connection-profile/setup/load")),
    ("profile Update", ("update profile", "profile update", "/connection-profile/setup/update")),
    ("profile Delete", ("delete profile", "profile delete", "/connection-profile/setup/delete")),
)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"cannot read {path.relative_to(ROOT)}: {exc}") from exc


def files_under(roots: Sequence[str]) -> list[Path]:
    found: set[Path] = set()
    for rel in roots:
        root = ROOT / rel
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
                found.add(path)
    return sorted(found)


def contains_any(text: str, needles: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(needle.lower() in lowered for needle in needles)


def entrypoints(files: Sequence[Path], expected_names: Sequence[str]) -> list[Path]:
    wanted = {name.lower() for name in expected_names}
    return [path for path in files if path.name.lower() in wanted]


def require_group(
    failures: list[str], platform: str, scope: str, label: str, needles: Sequence[str]
) -> None:
    if not contains_any(scope, needles):
        failures.append(f"{platform}: missing recovered UI contract: {label}")


def audit_platform(
    platform: str,
    roots: Sequence[str],
    expected_entries: Sequence[str],
    native_markers: Sequence[str],
) -> list[str]:
    failures: list[str] = []
    files = files_under(roots)
    if not files:
        return [f"{platform}: native source root missing or empty"]

    entries = entrypoints(files, expected_entries)
    if not entries:
        failures.append(
            f"{platform}: canonical native shipping entrypoint missing "
            f"({', '.join(expected_entries)})"
        )
        return failures

    entry_scope = "\n".join(read_text(path) for path in entries)
    platform_scope = "\n".join(read_text(path) for path in files)

    if not contains_any(entry_scope + "\n" + platform_scope, native_markers):
        failures.append(f"{platform}: native-platform implementation markers missing")

    # Cross-platform semantic presence is checked here.  The release gate also
    # runs platform-aware audits to prove these sources are actually composed.
    for label, needles in PRODUCT_GROUPS:
        require_group(failures, platform, platform_scope, label, needles)
    for label, needles in SETTINGS_GROUPS:
        require_group(failures, platform, platform_scope, label, needles)
    for label, needles in PROFILE_CRUD:
        require_group(failures, platform, platform_scope, label, needles)

    return failures


def audit_controller_transactions() -> list[str]:
    controller = ROOT / "cmd/client"
    if not controller.is_dir():
        return ["shared controller: cmd/client missing"]
    files = [
        path for path in controller.rglob("*")
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES
    ]
    scope = "\n".join(read_text(path) for path in sorted(files))
    required = (
        ("connection ownership", ("beginconnectionoperation", "connection operation")),
        ("mutation ownership", ("beginmutationoperation", "mutation operation")),
        ("node-bound ownership", ("beginnodeboundoperation", "node-bound operation")),
        ("Fastest freshness", ("fastest",)),
        ("DNS freshness", ("dns retest", "dns_retest", "dns policy")),
        ("MTU freshness", ("mtu retest", "mtu_retest")),
        ("profile transactions", ("connection profile", "connection-profile")),
    )
    failures: list[str] = []
    for label, needles in required:
        if not contains_any(scope, needles):
            failures.append(f"shared controller: missing {label}")
    return failures


def main() -> int:
    failures: list[str] = []
    for name, (roots, entries, markers) in PLATFORMS.items():
        failures.extend(audit_platform(name, roots, entries, markers))
    failures.extend(audit_controller_transactions())

    if failures:
        print("RECOVERED NATIVE UI PRODUCT CONTRACT: FAIL")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("RECOVERED NATIVE UI PRODUCT CONTRACT: PASS")
    print("Platform shipping, build, artifact, rendered UI, and physical path proof remain separate gates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
