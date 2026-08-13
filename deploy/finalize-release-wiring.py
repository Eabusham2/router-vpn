#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WIRE = ROOT / "deploy/wire-release-gaps.py"
spec = importlib.util.spec_from_file_location("routervpn_wire_release_gaps", WIRE)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {WIRE}")
wire = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wire
spec.loader.exec_module(wire)


def patch_main_imports() -> bool:
    path = ROOT / "cmd/client/main.go"
    text = path.read_text(encoding="utf-8")
    old = '\t"encoding/base64"\n'
    if old not in text:
        return False
    # Atomic bundle staging owns base64 decoding after importProfileBundle is
    # migrated, so keeping the old direct-decoder import would fail Go builds.
    text = text.replace(old, "", 1)
    path.write_text(text, encoding="utf-8")
    return True


def patch_full_audit() -> bool:
    path = ROOT / "deploy/full-audit-v4.py"
    text = path.read_text(encoding="utf-8")
    old = '"derivedNodeID, proofErr := expectedNodeProofID(p)","p.NodeProofID = derivedNodeID"'
    new = '"newStagedBundle(","nodeProofIDFromWGConfig(wgData)","p.NodeProofID = derivedNodeID"'
    if old not in text:
        if new in text:
            return False
        raise RuntimeError("full-audit selected-node import contract changed unexpectedly")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return True


def main() -> int:
    wire.main()
    changed = []
    if patch_main_imports(): changed.append("cmd/client/main.go import cleanup")
    if patch_full_audit(): changed.append("deploy/full-audit-v4.py atomic import contract")
    print("final release wiring cleanup:", ", ".join(changed) if changed else "nothing (already finalized)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
