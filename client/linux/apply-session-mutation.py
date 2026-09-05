#!/usr/bin/env python3
"""Current Linux session-mutation transform layered over the frozen v1 table.

Two reviewed shipping-composition changes added three lines before every
routervpn-unified-shell-v8 session-mutation anchor: Tor added one include and one
handler; typed external nodes added one include. The exact-source SHA in v1 was
already updated to the resulting shell, so only those absolute anchor indices
move. All expected/replacement text remains unchanged and is still verified.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
V1 = HERE / "apply-session-mutation-v1.py"
spec = importlib.util.spec_from_file_location("routervpn_linux_session_mutation_v1", V1)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load frozen Linux session mutation baseline")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

name = "routervpn-unified-shell-v8.inc"
expected, changes = base.SPECS[name]
base.SPECS[name] = (
    expected,
    [(i1 + 3, i2 + 3, old, new) for i1, i2, old, new in changes],
)

# The wrapper is both the shipping CLI and the importable compatibility API used
# by the authoritative session-mutation audit. Keep one mutation implementation:
# the frozen v1 apply() operates on the adjusted SPECS table above.
apply = base.apply

if __name__ == "__main__":
    base.main()
