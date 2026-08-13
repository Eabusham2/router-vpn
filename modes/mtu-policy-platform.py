#!/usr/bin/env python3
"""Run the established MTU policy with platform-aware strict protection."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("routervpn_mtu_policy_core", HERE / "mtu-policy.py")
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load mtu-policy.py")
CORE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CORE
SPEC.loader.exec_module(CORE)


def enforce_platform_kill_switch() -> None:
    helper = HERE / "kill-switch-platform.py"
    proc = subprocess.run([sys.executable, str(helper), "apply"], text=True, capture_output=True, check=False)
    if proc.stderr:
        print(proc.stderr.strip(), file=sys.stderr)
    if proc.returncode != 0:
        raise RuntimeError("strict platform kill switch could not be enforced; refusing to start the VPN runtime")


CORE.enforce_kill_switch = enforce_platform_kill_switch
raise SystemExit(CORE.main())
