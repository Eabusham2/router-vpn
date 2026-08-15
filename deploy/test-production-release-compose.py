#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/materialize-production-compose.py"
SOURCE = ROOT / "server/portainer-current.yaml"
TARGET = "a" * 40
DOCS = [ROOT / "docs/CURRENT-GUIDE.md", ROOT / "USE-CURRENT.md"]


def main() -> int:
    original = SOURCE.read_bytes()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / f"portainer-{TARGET}.yaml"
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--sha",
                TARGET,
                "--input",
                str(SOURCE),
                "--output",
                str(out),
            ],
            cwd=ROOT,
            check=True,
        )
        rendered = out.read_text(encoding="utf-8")
        assert TARGET in rendered
        assert "GENERATED exact-SHA Router VPN production compose: " + TARGET in rendered
        assert "ghcr.io/sagernet/sing-box:v1.13.12" in rendered
        assert "ghcr.io/xtls/xray-core:26.7.11" in rendered
        assert "ROUTER_VPN_GITHUB_SHA: " + TARGET in rendered
        assert SOURCE.read_bytes() == original, "materializer mutated tracked template"

        for path in DOCS:
            text = path.read_text(encoding="utf-8")
            assert "Exact-SHA production compose" in text, f"{path} omits exact-SHA release workflow"
            assert "PRODUCTION-RELEASE.md" in text, f"{path} omits production release contract"
            assert "tracked" in text and "template" in text, f"{path} does not distinguish tracked template"

        bad = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--sha",
                "not-a-sha",
                "--input",
                str(SOURCE),
                "--output",
                str(out),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert bad.returncode != 0, bad
    print("production release compose materializer tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
