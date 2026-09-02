#!/usr/bin/env python3
"""Fail closed if Router VPN runtime scripts can disable ASUS acceleration.

Router VPN's ASUS integration must withdraw only Router-VPN-owned exposure when
its helper or AI Board is unhealthy. It must never trade normal household
LAN/WAN stability for exposure by disabling Runner, FlowCache, CTF, hardware
acceleration, or by installing broad built-in-chain policy changes.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOTS = ("server/", "router/", "scripts/", "client/")
EXCLUDED_PARTS = ("/test", "tests/", "-audit", "_audit", "/fixtures/")

FORBIDDEN = {
    "disable Broadcom hardware acceleration": re.compile(
        r"\bfcctl\b[^\n]*(?:--hw-accel|hw[-_ ]?accel)[^\n]*(?:\b0\b|\boff\b|\bdisable(?:d)?\b)",
        re.IGNORECASE,
    ),
    "disable Runner": re.compile(
        r"(?:\brunner\b[^\n]*(?:\boff\b|\bdisable(?:d)?\b)|"
        r"\bnvram\b[^\n]*\b(?:runner_disable|runner_disable_force)\s*=\s*1\b)",
        re.IGNORECASE,
    ),
    "disable FlowCache/CTF": re.compile(
        r"(?:\bflow\s*cache\b[^\n]*(?:\boff\b|\bdisable(?:d)?\b)|"
        r"\bflowcache\b[^\n]*(?:\boff\b|\bdisable(?:d)?\b)|"
        r"\bnvram\b[^\n]*\b(?:fc_disable|ctf_disable|ctf_fa_mode)\s*=\s*1\b)",
        re.IGNORECASE,
    ),
    # Stay inside the iptables command segment.  A read-only command such as
    # `iptables -S FORWARD | grep -F TAG` must not be mistaken for
    # `iptables -F FORWARD` merely because a later pipeline stage uses -F.
    "flush a built-in IPv4/IPv6 chain": re.compile(
        r"\bip6?tables\b[^|;&\n]*(?:\s-F(?:\s|$)|\s--flush(?:\s|$))"
        r"(?:[^|;&\n]*\b(?:INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING)\b|\s*$)",
        re.IGNORECASE,
    ),
    "change a built-in IPv4/IPv6 default policy": re.compile(
        r"\bip6?tables\b[^|;&\n]*(?:\s-P|\s--policy)\s+"
        r"(?:INPUT|OUTPUT|FORWARD)\s+(?:DROP|REJECT)\b",
        re.IGNORECASE,
    ),
}


def tracked_runtime_shells() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "*.sh"], cwd=ROOT, check=True, text=True, capture_output=True
    )
    result: list[Path] = []
    for raw in proc.stdout.splitlines():
        path = raw.strip()
        if not path or not path.startswith(RUNTIME_ROOTS):
            continue
        lowered = "/" + path.lower()
        if any(part in lowered for part in EXCLUDED_PARTS):
            continue
        result.append(ROOT / path)
    return result


def main() -> None:
    files = tracked_runtime_shells()
    if not files:
        raise SystemExit("router acceleration safety audit found no runtime shell files")
    violations: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(ROOT)
        for description, pattern in FORBIDDEN.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                excerpt = " ".join(match.group(0).strip().split())[:240]
                violations.append(f"{rel}:{line}: {description}: {excerpt}")
    if violations:
        raise SystemExit(
            "Router VPN ASUS/household acceleration safety audit failed:\n"
            + "\n".join(f"- {item}" for item in violations)
        )
    print(
        "Router VPN ASUS/household acceleration safety audit: PASS "
        f"({len(files)} runtime shell files; Runner/FlowCache/HW acceleration untouched)"
    )


if __name__ == "__main__":
    main()
