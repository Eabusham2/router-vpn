#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys


def cleanup(root_value: str, target_value: str) -> None:
    root = Path(root_value).expanduser().resolve()
    run_root = (root / "run").resolve()
    target = Path(target_value).expanduser().resolve()
    try:
        rel = target.relative_to(run_root)
    except ValueError as exc:
        raise RuntimeError("refusing cleanup outside HOMEVPN_ROOT/run") from exc
    if not rel.parts or rel.parts[0] not in {"multihop", "native-multihop"}:
        raise RuntimeError("refusing cleanup of unrelated runtime path")
    if len(rel.parts) > 2:
        raise RuntimeError("refusing unexpectedly deep runtime cleanup path")
    if target == run_root:
        raise RuntimeError("refusing cleanup of the run root")
    if target.exists():
        shutil.rmtree(target)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: cleanup-private-runtime.py RUNTIME_DIR", file=sys.stderr)
        return 2
    root = os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client")
    try:
        cleanup(root, sys.argv[1])
        return 0
    except Exception as exc:
        print(f"private runtime cleanup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
