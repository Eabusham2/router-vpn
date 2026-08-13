#!/usr/bin/env python3
"""Run the established SMART/CUSTOM orchestrator with platform-safe cleanup."""
from __future__ import annotations

from pathlib import Path

source = Path(__file__).with_name("orchestrate.py")
text = source.read_text(encoding="utf-8")
old = 'str(SCRIPT_DIR / "stop-mode.sh")'
new = 'str(SCRIPT_DIR / "stop-mode-platform.sh")'
if old not in text:
    raise SystemExit("orchestrator cleanup contract drifted")
text = text.replace(old, new)
code = compile(text, str(source), "exec")
namespace = {
    "__name__": "__main__",
    "__file__": str(source),
    "__package__": None,
}
exec(code, namespace, namespace)
