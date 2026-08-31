#!/usr/bin/env python3
"""Reject WAN/router forwarding of Router VPN private management ports."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOTS = ("server/", "router/", "scripts/", "client/")
EXCLUDED = ("/test", "tests/", "-audit", "_audit", "/fixtures/")
PRIVATE_PORTS = {22, 1080, *range(8786, 8794), 9443, 45999}
EXPOSURE = re.compile(
    r"(?:\bDNAT\b|--to-destination|--dport|--dports|\bWAN[_ -]?PORT\b|"
    r"\bPUBLIC[_ -]?PORT\b|\bwan[_ -]?forward\b|\bport[_ -]?forward\b)",
    re.IGNORECASE,
)
PORT_TOKEN = re.compile(r"(?<![0-9])([0-9]{1,5})(?![0-9])")


def runtime_shells() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "*.sh"], cwd=ROOT, check=True, text=True, capture_output=True
    )
    files: list[Path] = []
    for raw in proc.stdout.splitlines():
        path = raw.strip()
        if not path.startswith(RUNTIME_ROOTS):
            continue
        lowered = "/" + path.lower()
        if any(part in lowered for part in EXCLUDED):
            continue
        files.append(ROOT / path)
    return files


def uncommented_shell_line(raw: str) -> str:
    # Exposure commands are expected to be ordinary shell, not quoted prose.
    # Remove full-line comments and trailing comments without attempting to
    # interpret arbitrary shell expansions.
    stripped = raw.lstrip()
    if not stripped or stripped.startswith("#"):
        return ""
    return raw.split(" #", 1)[0]


def main() -> None:
    files = runtime_shells()
    if not files:
        raise SystemExit("private-port exposure audit found no runtime shell files")

    violations: list[str] = []
    for path in files:
        rel = path.relative_to(ROOT)
        for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            line = uncommented_shell_line(raw)
            if not line or not EXPOSURE.search(line):
                continue
            ports = {int(match.group(1)) for match in PORT_TOKEN.finditer(line)}
            exposed = sorted(ports & PRIVATE_PORTS)
            if exposed:
                violations.append(
                    f"{rel}:{number}: private/admin port(s) {exposed} in exposure rule: "
                    + " ".join(line.strip().split())[:260]
                )

    if violations:
        raise SystemExit(
            "Router VPN private/admin WAN exposure audit failed:\n"
            + "\n".join(f"- {item}" for item in violations)
        )

    print(
        "Router VPN private/admin WAN exposure audit: PASS "
        f"({len(files)} runtime shell files; protected ports={sorted(PRIVATE_PORTS)})"
    )


if __name__ == "__main__":
    main()
