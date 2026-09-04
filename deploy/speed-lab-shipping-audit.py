#!/usr/bin/env python3
"""Authoritative Router VPN Speed Lab source/shipping contract."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing Speed Lab shipping source: {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing Speed Lab marker {marker!r}")


def forbid(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden Speed Lab marker {marker!r}")


# Shared desktop controller: current path is identity-bound, temporary paths are
# transactional/non-persistent, and real Mbps + idle/loaded latency are distinct.
need(
    "cmd/client/speed_lab_measure.go",
    "speedLabAutoMin     = 4 * time.Second",
    "speedLabAutoMax     = 12 * time.Second",
    "1s <= min <= max <= 60s",
    "idle_latency",
    "loaded_latency",
    "bufferbloat_ms",
    "speedLabStable",
    "speedLabDownloadRound",
    "speedLabUploadRound",
    "speedLabStreamCount",
    "speedLabParallelRound",
    "MaxConnsPerHost = 8",
    "adaptive 1-%d concurrent streams",
    "no latency probes succeeded",
)
need(
    "cmd/client/speed_lab_paths.go",
    "captureSpeedLabIdentity",
    "validateSpeedLabIdentity",
    "speedLabSnapshotTemporary",
    "speedLabRestoreTemporary",
    "system-direct",
    "multihop",
    "external",
    "temporary proven multihop graph",
    "temporary external direct/hopped exit",
)
need(
    "cmd/client/speed_lab.go",
    "/api/speed-lab/options",
    "/api/speed-lab/run",
    "download_loaded_ms",
    "upload_loaded_ms",
    "download_bufferbloat_ms",
    "upload_bufferbloat_ms",
    "beginSpeedLabTemporaryPersistenceGuard",
    "speedLabWriteStore(snapshot.Profiles)",
    "temporary path choices are restored after the test",
)
need(
    "cmd/client/speed_lab_persistence_guard.go",
    "speedLabTemporaryPersistenceSuppressed",
    "temporary Speed Lab persistence guard",
)
need("cmd/client/usage_metadata.go", "speedLabTemporaryPersistenceSuppressed(a)")

# Windows native WPF surface.
need(
    "client/RouterVPN-Windows-SpeedLab.ps1",
    "Router VPN Speed Lab",
    "Current path",
    "Temporary config",
    "System direct",
    "Router VPN node",
    "Multihop",
    "External exit / hop",
    "IDLE LATENCY",
    "DOWNLOAD",
    "UPLOAD",
    "loaded",
    "bufferbloat",
    "Auto timing",
    "Custom timing",
    'Minimum="1" Maximum="60"',
    "min_seconds",
    "max_seconds",
    "DAITA",
    "Jumbo",
    "Require encrypted AUTO",
    "Require obfuscation AUTO",
)
need("client/RouterVPN-Windows-App.ps1", "RouterVPN-Windows-SpeedLab.ps1", "Add-RouterVPNSpeedLabWindowsShell")

# macOS native AppKit surface and build composition.
need(
    "client/macos/RouterVPNMacSpeedLab.swift",
    "Router VPN Speed Lab",
    "current",
    "temporary",
    "system-direct",
    "multihop",
    "external",
    "min_seconds",
    "max_seconds",
    "loaded_latency",
    "bufferbloat",
    "daita",
    "jumbo",
    "require_encrypted",
    "require_obfuscation",
)
need("client/macos/build-native-app.sh", "RouterVPNMacSpeedLab.swift")

# Linux native GTK surface and compiled include.
need(
    "client/linux/routervpn-speed-lab-v12.inc",
    "Speed Lab",
    "current",
    "temporary",
    "system-direct",
    "multihop",
    "external",
    "min_seconds",
    "max_seconds",
    "loaded_latency",
    "bufferbloat",
    "require_encrypted",
    "require_obfuscation",
)
need("client/linux/build-native-app.sh", "routervpn-speed-lab-v12.inc")

# Android owns its own VpnService dataplane, so Speed Lab must use process-owned
# session/path identity and native temporary connect/disconnect transactions.
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeStateStore.java",
    "pathProof",
    'putString("path_proof", "passed")',
    "path_generation",
    "generation=p.getLong(\"path_generation\",0L)+1L",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLab.java",
    "DurationPolicy.normalize",
    "1s <= min <= max <= 60s",
    "loadedLatency",
    "bufferbloatMs",
    "StalePathException",
    "pathGeneration",
    "activeExternalId",
    "runtimeMode",
    '"passed".equals(now.pathProof)',
    "ParallelRound",
    "parallelRound",
    "streamCount",
    "Math.min(32<<20,v)",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLabController.java",
    'scope="current"',
    '"system-direct"',
    '"multihop"',
    '"external"',
    "connectNode",
    "connectMultihop",
    "connectExternal",
    "connection.disconnect",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLabDialog.java",
    "Router VPN path performance",
    "Current path",
    "Temporary config",
    "Min 4 s",
    "Max 12 s",
    "loaded",
    "bufferbloat",
)
need("android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java", "AndroidSpeedLabDialog")

# iPhone/iPad use their native PacketTunnel model rather than the desktop HTTP
# controller. Current/temporary path identity is watched continuously; unsupported
# desktop-equivalent multihop remains unavailable instead of being simulated.
need(
    "ios/RouterVPN/App/IOSSpeedLab.swift",
    "Router VPN Speed Lab",
    "4, maxSeconds: 12",
    "1s ≤ min ≤ max ≤ 60s",
    "loadedLatency",
    "bufferbloatMs",
    "speed.cloudflare.com",
    "stable(rates)",
    "parallelRound",
    "streamCount",
    "32 << 20",
    "withThrowingTaskGroup",
)
need(
    "ios/RouterVPN/App/IOSSpeedLabPersistenceJournal.swift",
    "router-vpn.speed-lab-journal-v1",
    "originalBundle",
    "originalLastRuntime",
    "reassertOriginalPersistentState",
    "recoverIfNeeded",
    "Temporary Speed Lab tunnel",
)
need(
    "ios/RouterVPN/App/IOSSpeedLabRunner.swift",
    "case current",
    "case temporary",
    'case systemDirect = "system-direct"',
    "case router",
    "case external",
    "case multihop",
    "Desktop-style multihop is intentionally unavailable on iOS/iPadOS",
    "guardedMeasurement",
    "Temporary Speed Lab tunnel did not fully stop",
    "IOSSpeedLabPersistenceJournal.begin",
    "IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState",
    "IOSSpeedLabPersistenceJournal.finish",
    "Recovery journal retained for next launch",
)
need(
    "ios/RouterVPN/App/IOSSpeedLabView.swift",
    "Router VPN Speed Lab",
    "Current config",
    "Temporary config",
    "Auto / default",
    "Custom",
    "Minimum",
    "Maximum",
    "Idle",
    "Download",
    "Upload",
    "Loaded Δ",
    "bufferbloat",
)
need("ios/RouterVPN/App/ProductRootView.swift", "Open Router VPN Speed Lab", "IOSSpeedLabView()", "IOSSpeedLabPersistenceJournal.recoverIfNeeded")
forbid("ios/RouterVPN/App/IOSSpeedLabRunner.swift", "fake multihop", "pretend multihop")

if errors:
    print("SPEED LAB SHIPPING AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("SPEED LAB SHIPPING AUDIT: PASS")
