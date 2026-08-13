#!/usr/bin/env python3
"""Recovered-contract release scorer layered over weighted-release-audit.py.

The historical 88/12 source/manual split is preserved. The original 88 source
points over-credited broad implementation buckets while omitting explicit
requirements recovered from the project history. This scorer scales the legacy
source gates to 84 points and assigns the reclaimed 4 points to those recovered
source requirements. The 12 manual/live points remain exactly unchanged.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "deploy" / "weighted-release-audit.py"

spec = importlib.util.spec_from_file_location("routervpn_weighted_release", LEGACY)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load weighted-release-audit.py")
legacy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = legacy
spec.loader.exec_module(legacy)


def body(rel: str) -> str:
    path = ROOT / rel
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def has(rel: str, *parts: str) -> bool:
    text = body(rel)
    return bool(text) and all(part in text for part in parts)


def no(rel: str, *parts: str) -> bool:
    text = body(rel)
    return bool(text) and all(part not in text for part in parts)


RECOVERED = [
    {
        "name": "strict macOS kill-switch enforcement",
        "weight": 1.0,
        "pass": lambda: (
            has("modes/kill-switch.py", "darwin", "apply_darwin")
            and has("modes/darwin_kill_switch.py", "com.apple/router-vpn", "pfctl", "utun")
            and has("cmd/client/main.go", "HOMEVPN_KILLSWITCH_REFRESH=1")
        ),
        "note": "must be wired fail-closed, not merely an orphan PF helper",
    },
    {
        "name": "authenticated release/update status and safe recovery surface",
        "weight": 0.5,
        "pass": lambda: (
            has("server/scripts/setup-center-ai-server.py", "setup_center_release_status.py", "/api/release-status", "_require_auth()")
            and has("server/scripts/setup_center_release_status.py", "exact-sha-image-only", "self_update_available", "safe_sequence")
            and no("server/portainer-current.yaml", "build:")
        ),
        "note": "status/recovery may remain read-only; Setup Center must not gain unsafe Docker authority",
    },
    {
        "name": "native connection-attempt progress consumes typed session events",
        "weight": 0.5,
        "pass": lambda: all(
            "/api/session/events" in body(rel)
            for rel in (
                "client/RouterVPN-Windows-App.ps1",
                "client/macos/RouterVPNMacApp.swift",
                "client/linux/routervpn-gtk.c",
            )
        ),
        "note": "native apps must surface attempt/fallback/rollback progress rather than polling only coarse status",
    },
    {
        "name": "selected DNS end-to-end proof plumbing",
        "weight": 0.5,
        "pass": lambda: (
            has("cmd/client/session_state.go", "DNSProof", "passed")
            and any(marker in body("cmd/client/extras.go") for marker in ("/api/dns/proof", "selected DNS proof"))
        ),
        "note": "benchmarking the home resolver alone is not proof the client is using the selected resolver",
    },
    {
        "name": "desktop multihop platform parity",
        "weight": 0.5,
        "pass": lambda: (
            no("cmd/client/multihop.go", 'runtime.GOOS != "linux"')
            and all("/api/multihop" in body(rel) for rel in (
                "client/RouterVPN-Windows-App.ps1",
                "client/macos/RouterVPNMacApp.swift",
                "client/linux/routervpn-gtk.c",
            ))
        ),
        "note": "Linux-only desktop controller multihop does not satisfy Windows/macOS parity",
    },
    {
        "name": "native product information architecture and real-coordinate map parity",
        "weight": 1.0,
        "pass": lambda: (
            has("internal/common/types.go", "Latitude", "Longitude", "LatencyMedianMs")
            and all("Map" in body(rel) for rel in (
                "client/RouterVPN-Windows-App.ps1",
                "client/macos/RouterVPNMacApp.swift",
                "client/linux/routervpn-gtk.c",
                "android/app/src/main/java/com/eabusham/routervpn/MainActivity.java",
                "ios/RouterVPN/App/ContentView.swift",
            ))
        ),
        "note": "native window existence is not the requested Home/Nodes+Map/Modes/DNS/Advanced/Forwarding/Settings/Help product parity",
    },
]


def main() -> int:
    legacy_source_total = sum(g.weight for g in legacy.GATES if g.kind == "source")
    legacy_manual_total = sum(g.weight for g in legacy.GATES if g.kind != "source")
    if abs(legacy_source_total - 88.0) > 0.001 or abs(legacy_manual_total - 12.0) > 0.001:
        raise SystemExit(f"legacy allocation drifted: source={legacy_source_total}, manual={legacy_manual_total}")

    legacy_source_earned = 0.0
    legacy_manual_earned = 0.0
    legacy_rows = []
    for gate in legacy.GATES:
        try:
            ok = bool(gate.check())
        except Exception:
            ok = False
        if gate.kind == "source" and ok:
            legacy_source_earned += gate.weight
        elif gate.kind != "source" and ok:
            legacy_manual_earned += gate.weight
        legacy_rows.append({"name": gate.name, "kind": gate.kind, "weight": gate.weight, "pass": ok})

    recovered_rows = []
    recovered_earned = 0.0
    for gate in RECOVERED:
        try:
            ok = bool(gate["pass"]())
        except Exception:
            ok = False
        if ok:
            recovered_earned += float(gate["weight"])
        recovered_rows.append({
            "name": gate["name"],
            "kind": "source-recovered",
            "weight": gate["weight"],
            "pass": ok,
            "note": gate["note"],
        })

    recovered_total = sum(float(g["weight"]) for g in RECOVERED)
    if abs(recovered_total - 4.0) > 0.001:
        raise SystemExit(f"recovered source weights sum to {recovered_total}, expected 4")

    # Legacy source gates now occupy 84 rather than 88 points. Scaling avoids
    # double-counting and preserves their relative importance when a legacy gate
    # itself fails. Recovered gates occupy the reclaimed 4 points.
    scaled_legacy_source = legacy_source_earned * (84.0 / 88.0)
    source_earned = scaled_legacy_source + recovered_earned
    total_earned = source_earned + legacy_manual_earned

    result = {
        "score_percent": round(total_earned, 2),
        "source_earned": round(source_earned, 2),
        "source_weight": 88.0,
        "manual_live_earned": round(legacy_manual_earned, 2),
        "manual_live_weight": 12.0,
        "legacy_machine_score_before_reconciliation": round(legacy_source_earned + legacy_manual_earned, 2),
        "recovered_source_earned": round(recovered_earned, 2),
        "recovered_source_weight": 4.0,
        "recovered_gates": recovered_rows,
        "legacy_gates": legacy_rows,
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
