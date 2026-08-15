#!/usr/bin/env python3
"""Run the MTU throughput tuner with the platform-aware Unix kill switch."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("routervpn_mtu_throughput_core", HERE / "mtu-throughput-tuner.py")
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load mtu-throughput-tuner.py")
CORE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CORE
SPEC.loader.exec_module(CORE)


def enforce_platform_kill_switch() -> None:
    helper = HERE / "kill-switch-platform.py"
    proc = subprocess.run([sys.executable, str(helper), "apply"], text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError("strict platform kill switch could not be enforced before MTU optimization" + (": " + detail if detail else ""))


CORE.enforce_kill_switch = enforce_platform_kill_switch
raise SystemExit(CORE.main())
