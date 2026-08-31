#!/usr/bin/env python3
"""Audit exact-SHA source snapshots as durable release evidence."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/source-snapshot.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"source snapshot durability audit failed: {message}")


def main() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    require("workflow_call:" in text, "source snapshot is not callable by authoritative release workflows")
    require("workflow_dispatch:" in text, "source snapshot cannot be regenerated on demand")
    require("git archive" in text and "HEAD" in text, "archive is not built from the exact checked-out commit")
    require("GITHUB_SHA" in text, "artifact identity is not bound to the exact source SHA")
    require("tree_sha" in text and "source_sha" in text, "machine-readable commit/tree identity manifest is missing")
    require("sha256sum" in text and "sha256sum -c" in text, "archive checksum is not created and verified")
    require("if-no-files-found: error" in text, "missing source evidence does not fail closed")
    require("Publish artifact pointer on exact commit" in text, "exact-commit artifact pointer is not published")
    require("steps.upload.outputs.artifact-id" in text, "status cannot prove the artifact that was actually uploaded")

    retention = re.search(r"(?m)^\s*retention-days:\s*(\d+)\s*$", text)
    require(retention is not None, "artifact retention is not explicit")
    require(int(retention.group(1)) >= 14, "exact-source evidence expires before a realistic release audit can finish")

    lowered = text.lower()
    for moving in ("releases/latest", "latest.zip", "refs/heads/main"):
        require(moving not in lowered, f"moving source fallback is present: {moving}")

    print(
        "Exact-SHA source snapshot durability audit: PASS "
        f"(retention={retention.group(1)} days; commit/tree/checksum identity required)"
    )


if __name__ == "__main__":
    main()
